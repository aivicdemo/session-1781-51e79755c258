// AIVIC Backend Configuration
// AIVIC_APP_URL 環境変数が設定されている場合は自動セットされます
// 未設定の場合: REPLACE_WITH_API_URL を AIVIC アプリの URL（例: https://your-app.amplifyapp.com）に書き換えてください

window.AIVIC_API_URL = "REPLACE_WITH_API_URL";
window.AIVIC_TABLES = {
  "営業データ": 0,
  "営業データ項目メタデータ": 1,
  "検証ルール": 2,
  "検証ルール条件": 3,
  "検証実行履歴": 4,
  "検証エラー": 5,
  "サービス": 6,
  "請求対象項目マッピング": 7,
  "請求集計": 8,
  "顧客別請求額": 9,
  "サービス別請求額": 10,
  "月次サマリーテンプレート": 11,
  "月次サマリーテンプレート項目": 12,
  "月次サマリー": 13,
  "データ品質通知": 14
};
