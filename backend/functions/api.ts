import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import {
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
  UpdateCommand,
  DeleteCommand,
  ScanCommand,
  QueryCommand,
  BatchWriteCommand,
} from '@aws-sdk/lib-dynamodb';
import { randomUUID } from 'crypto';
import { extractAuthContext, checkPermission, requireRole } from './rbac';

const client = new DynamoDBClient({});
const docClient = DynamoDBDocumentClient.from(client);
const TABLE_NAME = process.env.MAIN_TABLE || 'SalesDataQualitySystem';

interface AuditLog {
  pk: string;
  sk: string;
  userId: string;
  operationType: string;
  targetTable: string;
  targetId?: string;
  details: Record<string, unknown>;
  timestamp: number;
  result: 'SUCCESS' | 'FAILURE';
  errorMessage?: string;
}

interface User {
  id: string;
  email: string;
  username: string;
  passwordHash: string;
  organizationId: string;
  role: string;
  status: string;
  lastLoginAt?: number;
  createdAt: number;
  updatedAt: number;
  createdBy: string;
}

interface SalesData {
  id: string;
  userId: string;
  customerName: string;
  customerId?: string;
  transactionDate: number;
  productName: string;
  quantity: number;
  unitPrice: number;
  salesAmount: number;
  billingStatus: string;
  billingDate?: number;
  paymentDate?: number;
  notes?: string;
  createdAt: number;
  updatedAt: number;
  createdBy: string;
}

interface ValidationRule {
  id: string;
  salesDataItemId: string;
  ruleName: string;
  ruleType: string;
  validationCondition: string;
  errorLevel: string;
  errorMessage: string;
  autoFixFlag: boolean;
  fixLogic?: string;
  priority: number;
  activeFlag: boolean;
  startDate?: number;
  endDate?: number;
  createdAt: number;
  createdBy: string;
  updatedAt: number;
  updatedBy: string;
  notes?: string;
}

interface ValidationError {
  id: string;
  validationHistoryId: string;
  salesDataId: string;
  validationRuleId: string;
  salesDataItemId: string;
  errorType: string;
  errorMessage: string;
  detectedValue?: string;
  expectedValue?: string;
  severity: string;
  status: string;
  assignedUserId?: string;
  responseComment?: string;
  responseDate?: number;
  createdAt: number;
  updatedAt: number;
  createdBy: string;
}

interface Customer {
  id: string;
  name: string;
  nameKana?: string;
  code: string;
  industry?: string;
  region?: string;
  billingAddress?: string;
  billingPhone?: string;
  billingEmail?: string;
  assignedSalesUserId?: string;
  billingCycle?: string;
  billingStatus: string;
  contractStartDate?: number;
  contractEndDate?: number;
  createdAt: number;
  updatedAt: number;
  createdBy?: string;
  updatedBy?: string;
}

interface Service {
  id: string;
  name: string;
  description?: string;
  code: string;
  status: string;
  billableFlag: boolean;
  monthlyPrice?: number;
  createdAt: number;
  updatedAt: number;
  createdBy: string;
  updatedBy?: string;
}

interface BillingAggregation {
  id: string;
  periodStartDate: number;
  periodEndDate: number;
  customerId: string;
  status: string;
  targetCount: number;
  totalAmount: number;
  taxAmount: number;
  totalAmountWithTax: number;
  errorCount: number;
  validationCompleteFlag: boolean;
  confirmedAt?: number;
  billingIssuedAt?: number;
  notes?: string;
  createdAt: number;
  createdBy: string;
  updatedAt: number;
  updatedBy: string;
}

interface CustomerBillingAmount {
  id: string;
  customerId: string;
  billingYearMonth: string;
  amount: number;
  taxAmount: number;
  totalAmount: number;
  status: string;
  targetCount: number;
  errorCount?: number;
  billingExecutedAt?: number;
  notes?: string;
  createdAt: number;
  createdBy: string;
  updatedAt: number;
  updatedBy: string;
}

interface ServiceBillingAmount {
  id: string;
  customerId: string;
  serviceId: string;
  billingAggregationId: string;
  billingYearMonth: string;
  amount: number;
  taxAmount: number;
  totalAmountWithTax: number;
  usageQuantity?: number;
  unitPrice?: number;
  status: string;
  createdAt: number;
  updatedAt: number;
  createdBy: string;
}

interface MonthlySummary {
  id: string;
  targetYearMonth: string;
  salesDataCount: number;
  validationExecutionCount: number;
  validationErrorCount: number;
  validationErrorRate: string;
  dataQualityScore: number;
  billingTargetCustomerCount: number;
  billingTargetServiceCount: number;
  billingTotalAmount: number;
  billingAggregationStatus: string;
  processStartedAt: number;
  processCompletedAt?: number;
  processStatus: string;
  notes?: string;
  createdAt: number;
  updatedAt: number;
  createdBy: string;
  updatedBy: string;
}

interface DataQualityNotification {
  id: string;
  validationErrorId: string;
  targetUserId: string;
  status: string;
  type: string;
  message: string;
  priority: string;
  firstNotifiedAt: number;
  readAt?: number;
  resolvedAt?: number;
  responseComment?: string;
  createdAt: number;
  updatedAt: number;
  createdBy: string;
}

type ResourceType = 'users' | 'salesData' | 'validationRules' | 'validationErrors' | 'customers' | 'services' | 'billingAggregations' | 'customerBillingAmounts' | 'serviceBillingAmounts' | 'monthlySummaries' | 'dataQualityNotifications';

const resourceTypes: ResourceType[] = [
  'users',
  'salesData',
  'validationRules',
  'validationErrors',
  'customers',
  'services',
  'billingAggregations',
  'customerBillingAmounts',
  'serviceBillingAmounts',
  'monthlySummaries',
  'dataQualityNotifications',
];

function getPkSk(resourceType: ResourceType, id?: string): { pk: string; sk: string } {
  const pk = resourceType.toUpperCase();
  const sk = id ? `${pk}#${id}` : pk;
  return { pk, sk };
}

async function createAuditLog(
  userId: string,
  operationType: string,
  targetTable: string,
  targetId: string | undefined,
  details: Record<string, unknown>,
  result: 'SUCCESS' | 'FAILURE',
  errorMessage?: string
): Promise<void> {
  const auditLog: AuditLog = {
    pk: 'AUDIT',
    sk: `AUDIT#${randomUUID()}#${Date.now()}`,
    userId,
    operationType,
    targetTable,
    targetId,
    details,
    timestamp: Date.now(),
    result,
    errorMessage,
  };

  await docClient.send(
    new PutCommand({
      TableName: TABLE_NAME,
      Item: auditLog,
    })
  );
}

function errorResponse(statusCode: number, message: string): APIGatewayProxyResult {
  return {
    statusCode,
    body: JSON.stringify({ error: message }),
  };
}

function successResponse(statusCode: number, data: unknown): APIGatewayProxyResult {
  return {
    statusCode,
    body: JSON.stringify(data),
  };
}

async function handleGetResources(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  try {
    const authContext = extractAuthContext(event);
    checkPermission(authContext, 'users:read');

    const result = await docClient.send(
      new ScanCommand({
        TableName: TABLE_NAME,
        FilterExpression: 'attribute_exists(pk)',
        Limit: 100,
      })
    );

    const resources = result.Items || [];
    return successResponse(200, { resources, count: resources.length });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    return errorResponse(500, message);
  }
}

async function handleBulkImport(
  event: APIGatewayProxyEvent,
  resourceType: ResourceType
): Promise<APIGatewayProxyResult> {
  try {
    const authContext = extractAuthContext(event);
    checkPermission(authContext, 'bulk:import');

    const body = JSON.parse(event.body || '{}');
    const items = body.items || [];

    if (!Array.isArray(items) || items.length === 0) {
      return errorResponse(400, 'Invalid items array');
    }

    const { pk } = getPkSk(resourceType);
    const now = Date.now();
    const processedItems = items.map((item: Record<string, unknown>) => ({
      ...item,
      pk,
      sk: `${pk}#${item.id || randomUUID()}`,
      id: item.id || randomUUID(),
      createdAt: now,
      updatedAt: now,
      createdBy: authContext.userId,
    }));

    const chunks = [];
    for (let i = 0; i < processedItems.length; i += 25) {
      chunks.push(processedItems.slice(i, i + 25));
    }

    let imported = 0;
    let failed = 0;
    const errors: string[] = [];

    for (const chunk of chunks) {
      const requestItems: Record<string, unknown>[] = [];
      for (const item of chunk) {
        requestItems.push({
          PutRequest: {
            Item: item,
          },
        });
      }

      try {
        await docClient.send(
          new BatchWriteCommand({
            RequestItems: {
              [TABLE_NAME]: requestItems,
            },
          })
        );
        imported += chunk.length;
      } catch (chunkError) {
        failed += chunk.length;
        errors.push(
          chunkError instanceof Error ? chunkError.message : 'Batch write failed'
        );
      }
    }

    await createAuditLog(
      authContext.userId,
      'BULK_IMPORT',
      resourceType,
      undefined,
      { imported, failed, itemCount: items.length },
      'SUCCESS'
    );

    return successResponse(200, { imported, failed, errors });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    return errorResponse(500, message);
  }
}

async function handleGetResource(
  event: APIGatewayProxyEvent,
  resourceType: ResourceType
): Promise<APIGatewayProxyResult> {
  try {
    const authContext = extractAuthContext(event);
    checkPermission(authContext, `${resourceType}:read`);

    const id = event.pathParameters?.id;
    if (!id) {
      return errorResponse(400, 'Missing resource ID');
    }

    const { pk, sk } = getPkSk(resourceType, id);
    const result = await docClient.send(
      new GetCommand({
        TableName: TABLE_NAME,
        Key: { pk, sk },
      })
    );

    if (!result.Item) {
      return errorResponse(404, 'Resource not found');
    }

    return successResponse(200, result.Item);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    return errorResponse(500, message);
  }
}

async function handleListResources(
  event: APIGatewayProxyEvent,
  resourceType: ResourceType
): Promise<APIGatewayProxyResult> {
  try {
    const authContext = extractAuthContext(event);
    checkPermission(authContext, `${resourceType}:read`);

    const { pk } = getPkSk(resourceType);
    const result = await docClient.send(
      new QueryCommand({
        TableName: TABLE_NAME,
        KeyConditionExpression: 'pk = :pk',
        ExpressionAttributeValues: {
          ':pk': pk,
        },
        Limit: 100,
      })
    );

    const items = result.Items || [];
    return successResponse(200, { items, count: items.length });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    return errorResponse(500, message);
  }
}

async function handleCreateResource(
  event: APIGatewayProxyEvent,
  resourceType: ResourceType
): Promise<APIGatewayProxyResult> {
  try {
    const authContext = extractAuthContext(event);
    checkPermission(authContext, `${resourceType}:create`);

    const body = JSON.parse(event.body || '{}');
    const id = body.id || randomUUID();
    const now = Date.now();

    const { pk, sk } = getPkSk(resourceType, id);
    const item = {
      ...body,
      pk,
      sk,
      id,
      createdAt: now,
      updatedAt: now,
      createdBy: authContext.userId,
    };

    await docClient.send(
      new PutCommand({
        TableName: TABLE_NAME,
        Item: item,
      })
    );

    await createAuditLog(
      authContext.userId,
      'CREATE',
      resourceType,
      id,
      body,
      'SUCCESS'
    );

    return successResponse(201, item);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    return errorResponse(500, message);
  }
}

async function handleUpdateResource(
  event: APIGatewayProxyEvent,
  resourceType: ResourceType
): Promise<APIGatewayProxyResult> {
  try {
    const authContext = extractAuthContext(event);
    checkPermission(authContext, `${resourceType}:update`);

    const id = event.pathParameters?.id;
    if (!id) {
      return errorResponse(400, 'Missing resource ID');
    }

    const body = JSON.parse(event.body || '{}');
    const now = Date.now();

    const { pk, sk } = getPkSk(resourceType, id);

    const updateExpressions: string[] = [];
    const expressionAttributeValues: Record<string, unknown> = {};

    Object.entries(body).forEach(([key, value], index) => {
      if (key !== 'id' && key !== 'pk' && key !== 'sk' && key !== 'createdAt' && key !== 'createdBy') {
        updateExpressions.push(`${key} = :val${index}`);
        expressionAttributeValues[`:val${index}`] = value;
      }
    });

    updateExpressions.push('updatedAt = :updatedAt');
    updateExpressions.push('updatedBy = :updatedBy');
    expressionAttributeValues[':updatedAt'] = now;
    expressionAttributeValues[':updatedBy'] = authContext.userId;

    const result = await docClient.send(
      new UpdateCommand({
        TableName: TABLE_NAME,
        Key: { pk, sk },
        UpdateExpression: `SET ${updateExpressions.join(', ')}`,
        ExpressionAttributeValues: expressionAttributeValues,
        ReturnValues: 'ALL_NEW',
      })
    );

    await createAuditLog(
      authContext.userId,
      'UPDATE',
      resourceType,
      id,
      body,
      'SUCCESS'
    );

    return successResponse(200, result.Attributes);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    return errorResponse(500, message);
  }
}

async function handleDeleteResource(
  event: APIGatewayProxyEvent,
  resourceType: ResourceType
): Promise<APIGatewayProxyResult> {
  try {
    const authContext = extractAuthContext(event);
    checkPermission(authContext, `${resourceType}:delete`);

    const id = event.pathParameters?.id;
    if (!id) {
      return errorResponse(400, 'Missing resource ID');
    }

    const { pk, sk } = getPkSk(resourceType, id);

    await docClient.send(
      new DeleteCommand({
        TableName: TABLE_NAME,
        Key: { pk, sk },
      })
    );

    await createAuditLog(
      authContext.userId,
      'DELETE',
      resourceType,
      id,
      {},
      'SUCCESS'
    );

    return successResponse(204, null);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    return errorResponse(500, message);
  }
}

export async function handler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const path = event.path || '';
  const method = event.httpMethod || 'GET';

  try {
    if (path === '/resources' && method === 'GET') {
      return await handleGetResources(event);
    }

    const resourceMatch = path.match(/^\/api\/(\w+)(?:\/(\w+))?$/);
    if (!resourceMatch) {
      return errorResponse(404, 'Not found');
    }

    const resourceIndex = parseInt(resourceMatch[1], 10);
    const action = resourceMatch[2];

    if (resourceIndex < 0 || resourceIndex >= resourceTypes.length) {
      return errorResponse(400, 'Invalid resource index');
    }

    const resourceType = resourceTypes[resourceIndex];

    if (action === 'bulk' && method === 'POST') {
      return await handleBulkImport(event, resourceType);
    }

    if (method === 'GET' && !action) {
      return await handleListResources(event, resourceType);
    }

    if (method === 'GET' && action) {
      event.pathParameters = { id: action };
      return await handleGetResource(event, resourceType);
    }

    if (method === 'POST') {
      return await handleCreateResource(event, resourceType);
    }

    if (method === 'PUT' && action) {
      event.pathParameters = { id: action };
      return await handleUpdateResource(event, resourceType);
    }

    if (method === 'DELETE' && action) {
      event.pathParameters = { id: action };
      return await handleDeleteResource(event, resourceType);
    }

    return errorResponse(405, 'Method not allowed');
  } catch (error) {
    if (error instanceof Error && error.message.includes('Forbidden')) {
      return errorResponse(403, error.message);
    }
    const message = error instanceof Error ? error.message : 'Unknown error';
    return errorResponse(500, message);
  }
}