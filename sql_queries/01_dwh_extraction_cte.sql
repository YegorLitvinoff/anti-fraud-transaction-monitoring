-- ============================================================================
-- PROJECT: Fraud Volume Reduction
-- EXTENSION: 01_dwh_extraction_cte.sql
-- DESCRIPTION: Detecting fraudulent schemes (Smurfing and Mule Accounts) 
--              in DWH using CTEs, Window Functions, and complex JOINs.
-- ============================================================================

WITH transaction_cleansing AS (
    -- Step 1: Extract transactions from DWH, clean and normalize data types
    SELECT 
        tx.transaction_id,
        tx.client_id,
        tx.account_number_from,
        tx.account_number_to,
        tx.transaction_time,
        tx.amount,
        tx.currency,
        -- Convert transactional amounts to a unified currency baseline (EUR)
        CASE 
            WHEN tx.currency = 'RUB' THEN tx.amount / 95.0 
            WHEN tx.currency = 'KZT' THEN tx.amount / 500.0
            ELSE tx.amount 
        END AS amount_eur,
        tx.merchant_category_code AS mcc,
        tx.device_id,
        tx.ip_address
    FROM dwh.core_transactions tx
    WHERE tx.status = 'SUCCESS'
      -- Analyze historical dataset for critical attack periods
      AND tx.transaction_time BETWEEN '2025-01-01' AND '2025-12-31'
),

velocity_metrics AS (
    -- Step 2: Calculate time-series behavioral metrics using window functions
    SELECT 
        tc.*,
        -- Track the number of transfers within rolling 10-minute windows (Smurfing check)
        COUNT(tc.transaction_id) OVER(
            PARTITION BY tc.client_id 
            ORDER BY tc.transaction_time 
            RANGE BETWEEN INTERVAL '10 MINUTES' PRECEDING AND CURRENT ROW
        ) AS tx_count_10m,
        
        -- Compute cumulative transfer volumes over rolling 24-hour periods
        SUM(tc.amount_eur) OVER(
            PARTITION BY tc.client_id 
            ORDER BY tc.transaction_time 
            RANGE BETWEEN INTERVAL '24 HOURS' PRECEDING AND CURRENT ROW
        ) AS total_amount_24h,
        
        -- Capture baseline deviations from the immediate historical transaction
        LAG(tc.amount_eur, 1) OVER(
            PARTITION BY tc.client_id 
            ORDER BY tc.transaction_time
        ) AS previous_tx_amount,
        
        -- Flag hardware token rotation (unique devices bound to a single client)
        DENSE_RANK() OVER(
            PARTITION BY tc.client_id 
            ORDER BY tc.device_id
        ) AS unique_devices_count
    FROM transaction_cleansing tc
),

mule_accounts_detection AS (
    -- Step 3: Isolate suspicious transit nodes (Mule Accounts with rapid routing)
    SELECT 
        v.account_number_to AS suspected_mule_account,
        COUNT(DISTINCT v.client_id) AS unique_senders,
        SUM(v.amount_eur) AS total_inbound_volume,
        AVG(v.amount_eur) AS avg_inbound_tx
    FROM velocity_metrics v
    WHERE v.mcc IN ('6011', '6012') -- Cash outs and rapid financial routing categories
    GROUP BY v.account_number_to
    HAVING COUNT(DISTINCT v.client_id) >= 3 -- 3+ distinct originators sending funds to 1 target node
       AND SUM(v.amount_eur) > 5000         -- High-volume velocity traffic
)

-- Step 4: Final consolidation and real-time behavioral scoring output
SELECT 
    vm.transaction_id,
    vm.client_id,
    vm.transaction_time,
    vm.amount_eur,
    vm.tx_count_10m,
    vm.total_amount_24h,
    vm.ip_address,
    cl.risk_segment AS current_client_risk_segment,
    -- Evaluate risk flags based on compiled transactional aggregates
    CASE 
        WHEN ma.suspected_mule_account IS NOT NULL THEN 'CRITICAL: Target Mule Account Detected'
        WHEN vm.tx_count_10m > 5 AND vm.amount_eur < 150 THEN 'HIGH: Smurfing Pattern'
        WHEN vm.total_amount_24h > 10000 AND cl.risk_segment = 'LOW' THEN 'MEDIUM: Velocity Spike'
        ELSE 'LOW: Standard Transaction'
    END AS fraud_alert_level

FROM velocity_metrics vm
-- Join corporate directory to validate active client profiles
INNER JOIN dwh.client_profiles cl ON vm.client_id = cl.client_id
-- Merge mapped transit mule entities for real-time alerting
LEFT JOIN mule_accounts_detection ma ON vm.account_number_to = ma.suspected_mule_account
WHERE cl.is_active = TRUE
ORDER BY vm.transaction_time DESC
LIMIT 5000;
