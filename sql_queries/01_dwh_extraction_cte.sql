-- ============================================================================
-- PROJECT: Fraud Volume Reduction
-- EXTENSION: 01_dwh_extraction_cte.sql
-- DESCRIPTION: Выявление мошеннических схем (Smurfing и Mule-аккаунты) 
--              в DWH с использованием CTE, Window Functions и сложных JOIN.
-- ============================================================================

WITH transaction_cleansing AS (
    -- Шаг 1: Извлекаем транзакции из DWH, очищаем и нормализуем типы данных
    SELECT 
        tx.transaction_id,
        tx.client_id,
        tx.account_number_from,
        tx.account_number_to,
        tx.transaction_time,
        tx.amount,
        tx.currency,
        -- Переводим суммы в единую валюту (например, EUR, как в международном CV)
        CASE 
            WHEN tx.currency = 'RUB' THEN tx.amount / 95.0 -- условный курс
            WHEN tx.currency = 'KZT' THEN tx.amount / 500.0
            ELSE tx.amount 
        END AS amount_eur,
        tx.merchant_category_code AS mcc,
        tx.device_id,
        tx.ip_address
    FROM dwh.core_transactions tx
    WHERE tx.status = 'SUCCESS'
      -- Анализируем исторический массив за критический период атак
      AND tx.transaction_time BETWEEN '2025-01-01' AND '2025-12-31'
),

velocity_metrics AS (
    -- Шаг 2: Расчет поведенческих метрик во времени с помощью оконных функций
    SELECT 
        tc.*,
        -- Считаем количество транзакций клиента за последние 10 минут (веерная рассылка)
        COUNT(tc.transaction_id) OVER(
            PARTITION BY tc.client_id 
            ORDER BY tc.transaction_time 
            RANGE BETWEEN INTERVAL '10 MINUTES' PRECEDING AND CURRENT ROW
        ) AS tx_count_10m,
        
        -- Считаем кумулятивную сумму переводов клиента за последние 24 часа
        SUM(tc.amount_eur) OVER(
            PARTITION BY tc.client_id 
            ORDER BY tc.transaction_time 
            RANGE BETWEEN INTERVAL '24 HOURS' PRECEDING AND CURRENT ROW
        ) AS total_amount_24h,
        
        -- Вычисляем средний чек клиента за прошлый месяц для выявления аномальных всплесков
        LAG(tc.amount_eur, 1) OVER(
            PARTITION BY tc.client_id 
            ORDER BY tc.transaction_time
        ) AS previous_tx_amount,
        
        -- Проверяем смену устройств (уникальные девайсы на одного клиента)
        DENSE_RANK() OVER(
            PARTITION BY tc.client_id 
            ORDER BY tc.device_id
        ) AS unique_devices_count
    FROM transaction_cleansing tc
),

mule_accounts_detection AS (
    -- Шаг 3: Выявляем транзитные счета (Mule Accounts), куда деньги приходят и тут же уходят
    SELECT 
        v.account_number_to AS suspected_mule_account,
        COUNT(DISTINCT v.client_id) AS unique_senders,
        SUM(v.amount_eur) AS total_inbound_volume,
        AVG(v.amount_eur) AS avg_inbound_tx
    FROM velocity_metrics v
    WHERE v.mcc IN ('6011', '6012') -- Снятие наличных, финансовые институты (типичный вывод)
    GROUP BY v.account_number_to
    HAVING COUNT(DISTINCT v.client_id) >= 3 -- 3 и более разных отправителей на один счет за период
       AND SUM(v.amount_eur) > 5000         -- Крупный объем транзита
)

-- Шаг 4: Финальная склейка и скоринг для выгрузки в антифрод-мониторинг
SELECT 
    vm.transaction_id,
    vm.client_id,
    vm.transaction_time,
    vm.amount_eur,
    vm.tx_count_10m,
    vm.total_amount_24h,
    vm.ip_address,
    cl.risk_segment AS current_client_risk_segment,
    -- Присваиваем флаг подозрительной транзакции на основе агрегированных факторов
    CASE 
        WHEN ma.suspected_mule_account IS NOT NULL THEN 'CRITICAL: Target Mule Account Detected'
        WHEN vm.tx_count_10m > 5 AND vm.amount_eur < 150 THEN 'HIGH: Smurfing Pattern'
        WHEN vm.total_amount_24h > 10000 AND cl.risk_segment = 'LOW' THEN 'MEDIUM: Velocity Spike'
        ELSE 'LOW: Standard Transaction'
    END AS fraud_alert_level

FROM velocity_metrics vm
-- Джойним справочник клиентов для проверки их риск-профиля
INNER JOIN dwh.client_profiles cl ON vm.client_id = cl.client_id
-- Левое соединение с нашей таблицей выявленных дроп-счетов
LEFT JOIN mule_accounts_detection ma ON vm.account_number_to = ma.suspected_mule_account
WHERE cl.is_active = TRUE
ORDER BY vm.transaction_time DESC
LIMIT 5000;
