#!/usr/bin/env python3
"""
Create demo data in S4H for business impact scenarios:
1. Sales Orders (Revenue Dashboard scenario)
2. Production Orders (Production Sabotage scenario)

Uses sap_rfc_ctypes.py for all RFC calls.
"""
import sys
import json
import traceback

sys.path.insert(0, '/home/joris/Desktop/CLAUDE/SAPMAP')
from sap_rfc_ctypes import RFCConnection

SDK = '/home/joris/Desktop/nwrfc750P_18-70002752/nwrfcsdk/lib/libsapnwrfc.so'
CONN_PARAMS = dict(
    sdk_path=SDK,
    ashost='192.168.2.209',
    sysnr='00',
    client='001',
    user='joris',
    passwd='Schaap123!',
    lang='EN',
)


def read_table(conn, table, fields, max_rows=100, where=''):
    """Read SAP table via RFC_READ_TABLE and return list of dicts."""
    field_list = [{'FIELDNAME': f} for f in fields]
    kwargs = dict(
        QUERY_TABLE=table,
        DELIMITER='|',
        ROWCOUNT=max_rows,
        FIELDS=field_list,
    )
    if where:
        kwargs['OPTIONS'] = [{'TEXT': where}]
    try:
        result = conn.call('RFC_READ_TABLE', **kwargs)
    except Exception as e:
        print(f"  [ERROR] RFC_READ_TABLE on {table}: {e}")
        return []

    rows = []
    data_lines = result.get('DATA', [])
    for row in data_lines:
        wa = row.get('WA', '')
        vals = wa.split('|')
        d = {}
        for i, f in enumerate(fields):
            d[f] = vals[i].strip() if i < len(vals) else ''
        rows.append(d)
    return rows


def bapi_commit(conn):
    """Commit BAPI transaction."""
    try:
        result = conn.call('BAPI_TRANSACTION_COMMIT', WAIT='X')
        ret = result.get('RETURN', {})
        if ret and ret.get('TYPE') in ('E', 'A'):
            print(f"  [COMMIT ERROR] {ret.get('MESSAGE', '')}")
        return result
    except Exception as e:
        print(f"  [COMMIT ERROR] {e}")
        return {}


def bapi_rollback(conn):
    """Rollback BAPI transaction."""
    try:
        conn.call('BAPI_TRANSACTION_ROLLBACK')
    except Exception:
        pass


def print_return_messages(ret_list):
    """Print BAPI RETURN table messages."""
    if isinstance(ret_list, dict):
        ret_list = [ret_list]
    for msg in ret_list:
        if isinstance(msg, dict):
            t = msg.get('TYPE', '?')
            mid = msg.get('ID', '')
            num = msg.get('NUMBER', '')
            text = msg.get('MESSAGE', '')
            if text:
                print(f"    [{t}] {mid}-{num}: {text}")


# ============================================================================
# Phase 1: Query existing configuration
# ============================================================================

def query_config(conn):
    """Query all needed config tables and return a config dict."""
    config = {}

    print("=" * 70)
    print("PHASE 1: Querying existing configuration")
    print("=" * 70)

    # 1. Sales orgs from TVKO
    print("\n[1] Sales Organizations (TVKO)...")
    tvko = read_table(conn, 'TVKO', ['VKORG', 'VTWEG', 'SPART'])
    if tvko:
        for r in tvko:
            print(f"    VKORG={r['VKORG']}  VTWEG={r['VTWEG']}  SPART={r['SPART']}")
    else:
        print("    (empty or error)")
    config['tvko'] = tvko

    # 2. Distribution channels from TVTW
    print("\n[2] Distribution Channels (TVTW)...")
    tvtw = read_table(conn, 'TVTW', ['VTWEG', 'VTEXT'], max_rows=20)
    if tvtw:
        for r in tvtw:
            print(f"    VTWEG={r['VTWEG']}  {r.get('VTEXT','')}")
    else:
        print("    (empty or error)")
    config['tvtw'] = tvtw

    # 3. Divisions from TSPA
    print("\n[3] Divisions (TSPA)...")
    tspa = read_table(conn, 'TSPA', ['SPART'], max_rows=20)
    if tspa:
        for r in tspa:
            print(f"    SPART={r['SPART']}")
    else:
        print("    (empty or error)")
    config['tspa'] = tspa

    # 4. Customers from KNA1
    print("\n[4] Customers (KNA1, first 15)...")
    kna1 = read_table(conn, 'KNA1', ['KUNNR', 'NAME1'], max_rows=15)
    if kna1:
        for r in kna1:
            print(f"    KUNNR={r['KUNNR']}  NAME1={r['NAME1']}")
    else:
        print("    (empty or error)")
    config['kna1'] = kna1

    # 5. Materials from MARA
    print("\n[5] Materials (MARA, first 30)...")
    mara = read_table(conn, 'MARA', ['MATNR', 'MTART'], max_rows=30)
    if mara:
        for r in mara:
            print(f"    MATNR={r['MATNR']}  MTART={r['MTART']}")
    else:
        print("    (empty or error)")
    config['mara'] = mara

    # 6. Materials with sales views (MVKE)
    print("\n[6] Material Sales Views (MVKE)...")
    mvke = read_table(conn, 'MVKE', ['MATNR', 'VKORG', 'VTWEG'], max_rows=30)
    if mvke:
        for r in mvke:
            print(f"    MATNR={r['MATNR']}  VKORG={r['VKORG']}  VTWEG={r['VTWEG']}")
    else:
        print("    (empty or error - materials may lack sales views)")
    config['mvke'] = mvke

    # 7. Material plant data (MARC)
    print("\n[7] Material-Plant Data (MARC)...")
    marc = read_table(conn, 'MARC', ['MATNR', 'WERKS'], max_rows=30)
    if marc:
        for r in marc:
            print(f"    MATNR={r['MATNR']}  WERKS={r['WERKS']}")
    else:
        print("    (empty or error)")
    config['marc'] = marc

    # 8. Plants
    print("\n[8] Plants (T001W)...")
    t001w = read_table(conn, 'T001W', ['WERKS', 'NAME1'], max_rows=10)
    if t001w:
        for r in t001w:
            print(f"    WERKS={r['WERKS']}  NAME1={r['NAME1']}")
    else:
        print("    (empty or error)")
    config['t001w'] = t001w

    # 9. Company codes
    print("\n[9] Company Codes (T001)...")
    t001 = read_table(conn, 'T001', ['BUKRS', 'BUTXT'], max_rows=10)
    if t001:
        for r in t001:
            print(f"    BUKRS={r['BUKRS']}  BUTXT={r['BUTXT']}")
    else:
        print("    (empty or error)")
    config['t001'] = t001

    # 10. Production order types (T003O)
    print("\n[10] Order Types (T003O)...")
    t003o = read_table(conn, 'T003O', ['AUART'], max_rows=20)
    if t003o:
        for r in t003o:
            print(f"    AUART={r['AUART']}")
    else:
        print("    (empty or error)")
    config['t003o'] = t003o

    # 11. Customer sales data (KNVV) - needed for sold-to-party config
    print("\n[11] Customer Sales Data (KNVV)...")
    knvv = read_table(conn, 'KNVV', ['KUNNR', 'VKORG', 'VTWEG', 'SPART'], max_rows=20)
    if knvv:
        for r in knvv:
            print(f"    KUNNR={r['KUNNR']}  VKORG={r['VKORG']}  VTWEG={r['VTWEG']}  SPART={r['SPART']}")
    else:
        print("    (empty or error - customers may lack sales area assignment)")
    config['knvv'] = knvv

    # 12. Pricing conditions (if any)
    print("\n[12] Document types for sales (TVAK)...")
    tvak = read_table(conn, 'TVAK', ['AUART'], max_rows=20)
    if tvak:
        for r in tvak:
            print(f"    AUART={r['AUART']}")
    else:
        print("    (empty or error)")
    config['tvak'] = tvak

    return config


# ============================================================================
# Phase 2: Create Sales Orders
# ============================================================================

def create_sales_orders(conn, config):
    """Create sales orders using BAPI_SALESORDER_CREATEFROMDAT2."""
    print("\n" + "=" * 70)
    print("PHASE 2: Creating Sales Orders")
    print("=" * 70)

    # Determine sales org configuration
    tvko = config.get('tvko', [])
    knvv = config.get('knvv', [])
    mvke = config.get('mvke', [])
    kna1 = config.get('kna1', [])
    mara = config.get('mara', [])

    if not tvko:
        print("\n[!] No sales organizations found in TVKO. Cannot create sales orders.")
        return []

    # Pick the first sales org combo
    sales_org = tvko[0]['VKORG']
    dist_ch = tvko[0]['VTWEG']
    division = tvko[0]['SPART']
    print(f"\n[*] Using sales org={sales_org}, dist_ch={dist_ch}, division={division}")

    # Find customers with sales area assignment matching our org
    valid_customers = []
    if knvv:
        for r in knvv:
            if r['VKORG'] == sales_org and r['VTWEG'] == dist_ch:
                valid_customers.append(r['KUNNR'])
    if not valid_customers and kna1:
        print("  [!] No customers in KNVV for this sales org, trying all KNA1 customers...")
        valid_customers = [r['KUNNR'] for r in kna1]
    if not valid_customers:
        print("  [!] No customers available at all. Cannot create sales orders.")
        return []
    print(f"  [*] Candidate customers: {valid_customers[:10]}")

    # Find materials with sales views matching our org
    valid_materials = []
    if mvke:
        for r in mvke:
            if r['VKORG'] == sales_org:
                valid_materials.append(r['MATNR'])
    if not valid_materials and mara:
        print("  [!] No materials in MVKE for this sales org, trying all MARA materials...")
        valid_materials = [r['MATNR'] for r in mara]
    if not valid_materials:
        print("  [!] No materials available at all. Cannot create sales orders.")
        return []
    print(f"  [*] Candidate materials: {valid_materials[:10]}")

    # Determine document type for sales orders
    tvak = config.get('tvak', [])
    doc_type = 'TA'  # Standard order
    if tvak:
        # Try TA first, otherwise pick first available
        avail_types = [r['AUART'] for r in tvak]
        if 'TA' in avail_types:
            doc_type = 'TA'
        elif 'OR' in avail_types:
            doc_type = 'OR'
        else:
            doc_type = avail_types[0]
    print(f"  [*] Using document type: {doc_type}")

    # Define orders to create — mix of customers, materials, quantities
    import random
    random.seed(42)

    order_specs = []
    quantities = [10, 25, 50, 100, 200, 500, 1000, 5, 15, 75, 150, 300, 750, 2000, 50]
    prices = [500, 1000, 2000, 5000, 10000, 20000, 50000, 200, 800, 3000, 15000, 25000, 40000, 100000, 7500]

    for i in range(min(15, max(len(valid_customers), 5))):
        cust = valid_customers[i % len(valid_customers)]
        mat = valid_materials[i % len(valid_materials)]
        qty = quantities[i % len(quantities)]
        price = prices[i % len(prices)]
        order_specs.append({
            'customer': cust,
            'material': mat,
            'quantity': qty,
            'price': price,
        })

    created_orders = []

    for idx, spec in enumerate(order_specs):
        print(f"\n--- Sales Order {idx+1}/{len(order_specs)} ---")
        print(f"  Customer={spec['customer']}  Material={spec['material']}")
        print(f"  Qty={spec['quantity']}  Price={spec['price']} EUR")

        try:
            # Build BAPI parameters
            order_header = {
                'DOC_TYPE': doc_type,
                'SALES_ORG': sales_org,
                'DISTR_CHAN': dist_ch,
                'DIVISION': division,
                'PURCH_NO_C': f'SAPMAP-{idx+1:03d}',
            }

            order_partners = [
                {'PARTN_ROLE': 'AG', 'PARTN_NMBR': spec['customer']},  # Sold-to
            ]

            order_items = [
                {
                    'ITM_NUMBER': '000010',
                    'MATERIAL': spec['material'],
                    'TARGET_QTY': str(spec['quantity']),
                    'TARGET_QU': 'ST',  # piece
                },
            ]

            order_schedules = [
                {
                    'ITM_NUMBER': '000010',
                    'SCHED_LINE': '0001',
                    'REQ_QTY': str(spec['quantity']),
                },
            ]

            # Conditions for pricing (PR00 = price)
            order_conditions = [
                {
                    'ITM_NUMBER': '000010',
                    'COND_TYPE': 'PR00',
                    'COND_VALUE': str(spec['price']),
                    'CURRENCY': 'EUR',
                },
            ]

            result = conn.call(
                'BAPI_SALESORDER_CREATEFROMDAT2',
                ORDER_HEADER_IN=order_header,
                ORDER_PARTNERS=order_partners,
                ORDER_ITEMS_IN=order_items,
                ORDER_SCHEDULES_IN=order_schedules,
                ORDER_CONDITIONS_IN=order_conditions,
            )

            # Check result
            doc_number = result.get('SALESDOCUMENT', '')
            ret = result.get('RETURN', [])

            if doc_number and doc_number.strip() and doc_number.strip() != '0000000000':
                print(f"  [OK] Created sales order: {doc_number}")
                bapi_commit(conn)
                created_orders.append(doc_number.strip())
            else:
                print(f"  [FAIL] No document number returned")
                print_return_messages(ret)
                bapi_rollback(conn)

                # If first order fails, try without conditions (let system determine price)
                if idx == 0:
                    print("\n  [*] Retrying without pricing conditions...")
                    try:
                        result2 = conn.call(
                            'BAPI_SALESORDER_CREATEFROMDAT2',
                            ORDER_HEADER_IN=order_header,
                            ORDER_PARTNERS=order_partners,
                            ORDER_ITEMS_IN=order_items,
                            ORDER_SCHEDULES_IN=order_schedules,
                        )
                        doc2 = result2.get('SALESDOCUMENT', '')
                        ret2 = result2.get('RETURN', [])
                        if doc2 and doc2.strip() and doc2.strip() != '0000000000':
                            print(f"  [OK] Created sales order (no conditions): {doc2}")
                            bapi_commit(conn)
                            created_orders.append(doc2.strip())
                        else:
                            print(f"  [FAIL] Still no document number")
                            print_return_messages(ret2)
                            bapi_rollback(conn)
                    except Exception as e2:
                        print(f"  [ERROR] Retry failed: {e2}")
                        bapi_rollback(conn)

        except Exception as e:
            print(f"  [ERROR] {e}")
            traceback.print_exc()
            bapi_rollback(conn)

            # On first failure, try a simpler call
            if idx == 0:
                print("\n  [*] Trying minimal BAPI call...")
                try:
                    result_min = conn.call(
                        'BAPI_SALESORDER_CREATEFROMDAT2',
                        ORDER_HEADER_IN={
                            'DOC_TYPE': doc_type,
                            'SALES_ORG': sales_org,
                            'DISTR_CHAN': dist_ch,
                            'DIVISION': division,
                        },
                        ORDER_PARTNERS=[
                            {'PARTN_ROLE': 'AG', 'PARTN_NMBR': spec['customer']},
                        ],
                        ORDER_ITEMS_IN=[
                            {'ITM_NUMBER': '000010', 'MATERIAL': spec['material']},
                        ],
                        ORDER_SCHEDULES_IN=[
                            {'ITM_NUMBER': '000010', 'SCHED_LINE': '0001', 'REQ_QTY': '1'},
                        ],
                    )
                    doc_min = result_min.get('SALESDOCUMENT', '')
                    ret_min = result_min.get('RETURN', [])
                    if doc_min and doc_min.strip() and doc_min.strip() != '0000000000':
                        print(f"  [OK] Created minimal sales order: {doc_min}")
                        bapi_commit(conn)
                        created_orders.append(doc_min.strip())
                    else:
                        print(f"  [FAIL] Minimal call also failed")
                        print_return_messages(ret_min)
                        bapi_rollback(conn)
                except Exception as e3:
                    print(f"  [ERROR] Minimal call: {e3}")
                    bapi_rollback(conn)

    return created_orders


# ============================================================================
# Phase 3: Create Billing Documents
# ============================================================================

def create_billing_documents(conn, sales_orders):
    """Try to create billing documents from sales orders."""
    print("\n" + "=" * 70)
    print("PHASE 3: Creating Billing Documents")
    print("=" * 70)

    if not sales_orders:
        print("\n[!] No sales orders to bill. Skipping.")
        return []

    created_bills = []

    # Try BAPI_BILLINGDOC_CREATEMULTIPLE
    print(f"\n[*] Attempting to bill {len(sales_orders)} sales orders...")

    for so in sales_orders[:5]:  # Try up to 5
        print(f"\n  Billing sales order {so}...")
        try:
            result = conn.call(
                'BAPI_BILLINGDOC_CREATEMULTIPLE',
                SALESORDERS=[{'REF_DOC': so}],
            )
            ret = result.get('RETURN', [])
            success = result.get('SUCCESS', [])
            if success:
                for s in success:
                    bill_doc = s.get('BILL_DOC', '')
                    if bill_doc:
                        print(f"  [OK] Billing doc: {bill_doc}")
                        created_bills.append(bill_doc)
                bapi_commit(conn)
            else:
                print(f"  [FAIL] No billing document created")
                print_return_messages(ret)
                bapi_rollback(conn)
        except Exception as e:
            print(f"  [ERROR] {e}")
            bapi_rollback(conn)

    return created_bills


# ============================================================================
# Phase 4: Create Production Orders
# ============================================================================

def create_production_orders(conn, config):
    """Create production orders using BAPI_PRODORD_CREATE."""
    print("\n" + "=" * 70)
    print("PHASE 4: Creating Production Orders")
    print("=" * 70)

    marc = config.get('marc', [])
    mara = config.get('mara', [])
    t003o = config.get('t003o', [])

    if not marc:
        print("\n[!] No material-plant data (MARC). Cannot create production orders.")
        return []

    # Get materials with plant assignments
    plant_mats = [(r['MATNR'], r['WERKS']) for r in marc]
    print(f"\n[*] Materials with plant data: {len(plant_mats)}")
    for m, w in plant_mats[:10]:
        print(f"    {m} @ plant {w}")

    # Determine order type
    order_type = 'PP01'
    if t003o:
        avail = [r['AUART'] for r in t003o]
        for preferred in ['PP01', 'PP02', 'PP03', 'PI01']:
            if preferred in avail:
                order_type = preferred
                break
        else:
            if avail:
                order_type = avail[0]
    print(f"  [*] Using order type: {order_type}")

    created_orders = []
    quantities = [100, 250, 500, 1000, 2000]

    # Try BAPI_PRODORD_CREATE first
    print("\n[*] Trying BAPI_PRODORD_CREATE...")
    for idx in range(min(5, len(plant_mats))):
        mat, plant = plant_mats[idx]
        qty = quantities[idx % len(quantities)]
        print(f"\n  Production Order {idx+1}: Material={mat}, Plant={plant}, Qty={qty}")

        try:
            result = conn.call(
                'BAPI_PRODORD_CREATE',
                ORDERDATA={
                    'MATERIAL': mat,
                    'PLANT': plant,
                    'ORDER_TYPE': order_type,
                    'QUANTITY': str(qty),
                    'BASIC_START_DATE': '20260415',
                    'BASIC_END_DATE': '20260430',
                },
            )

            order_number = result.get('ORDER_NUMBER', '') or result.get('NUMBER', '')
            ret = result.get('RETURN', [])

            if order_number and order_number.strip():
                print(f"  [OK] Created production order: {order_number}")
                bapi_commit(conn)
                created_orders.append(order_number.strip())
            else:
                print(f"  [FAIL] No order number returned")
                print_return_messages(ret)
                bapi_rollback(conn)

        except Exception as e:
            print(f"  [ERROR] {e}")
            bapi_rollback(conn)

            # If first attempt fails, try planned orders as fallback
            if idx == 0:
                print("\n  [*] Trying BAPI_PLANNEDORDER_CREATE as fallback...")
                try:
                    result2 = conn.call(
                        'BAPI_PLANNEDORDER_CREATE',
                        PLANNED_ORDER={
                            'MATERIAL': mat,
                            'PLANT': plant,
                            'PLAN_OPEN_DATE': '20260415',
                            'PLAN_END_DATE': '20260430',
                            'TOTAL_PLORD_QTY': str(qty),
                        },
                    )
                    order2 = result2.get('NUMBER', '') or result2.get('PLANNEDORDER', '')
                    ret2 = result2.get('RETURN', [])
                    if order2 and order2.strip():
                        print(f"  [OK] Created planned order: {order2}")
                        bapi_commit(conn)
                        created_orders.append(order2.strip())
                    else:
                        print(f"  [FAIL] Planned order also failed")
                        print_return_messages(ret2)
                        bapi_rollback(conn)
                except Exception as e2:
                    print(f"  [ERROR] Planned order: {e2}")
                    bapi_rollback(conn)
                break  # Don't try more if basic call fails

    return created_orders


# ============================================================================
# Phase 5: Verify created data
# ============================================================================

def verify_data(conn, sales_orders, billing_docs, prod_orders):
    """Verify created data by reading from result tables."""
    print("\n" + "=" * 70)
    print("PHASE 5: Verification")
    print("=" * 70)

    # Check VBAK (sales order headers)
    print("\n[1] Sales Order Headers (VBAK)...")
    vbak = read_table(conn, 'VBAK', ['VBELN', 'AUART', 'VKORG', 'KUNNR', 'NETWR', 'WAERK'], max_rows=50)
    if vbak:
        print(f"  Found {len(vbak)} sales orders:")
        for r in vbak:
            print(f"    VBELN={r['VBELN']}  Type={r['AUART']}  Org={r['VKORG']}  "
                  f"Cust={r['KUNNR']}  Net={r['NETWR']} {r['WAERK']}")
    else:
        print("  (no sales orders found)")

    # Check VBAP (sales order items)
    print("\n[2] Sales Order Items (VBAP)...")
    vbap = read_table(conn, 'VBAP', ['VBELN', 'POSNR', 'MATNR', 'KWMENG', 'NETWR'], max_rows=50)
    if vbap:
        print(f"  Found {len(vbap)} line items:")
        for r in vbap:
            print(f"    VBELN={r['VBELN']}  Item={r['POSNR']}  "
                  f"Mat={r['MATNR']}  Qty={r['KWMENG']}  Net={r['NETWR']}")
    else:
        print("  (no sales order items found)")

    # Check billing docs (VBRK)
    if billing_docs:
        print("\n[3] Billing Documents (VBRK)...")
        vbrk = read_table(conn, 'VBRK', ['VBELN', 'FKART', 'NETWR', 'WAERK'], max_rows=20)
        if vbrk:
            print(f"  Found {len(vbrk)} billing documents:")
            for r in vbrk:
                print(f"    VBELN={r['VBELN']}  Type={r['FKART']}  Net={r['NETWR']} {r['WAERK']}")
        else:
            print("  (no billing documents found)")

    # Check production orders (AUFK)
    print("\n[4] Production/Planned Orders (AUFK)...")
    aufk = read_table(conn, 'AUFK', ['AUFNR', 'AUART', 'AUTYP', 'ERDAT', 'LOEKZ'], max_rows=20)
    if aufk:
        print(f"  Found {len(aufk)} orders in AUFK:")
        for r in aufk:
            print(f"    AUFNR={r['AUFNR']}  Type={r['AUART']}  OrdCat={r['AUTYP']}  "
                  f"Created={r['ERDAT']}  DelFlag={r['LOEKZ']}")
    else:
        print("  (no orders in AUFK)")

    # Also check AFKO for production order details
    print("\n[5] Production Order Details (AFKO)...")
    afko = read_table(conn, 'AFKO', ['AUFNR', 'PLNBEZ', 'GAMNG', 'GSTRS', 'GLTRP'], max_rows=20)
    if afko:
        print(f"  Found {len(afko)} production orders in AFKO:")
        for r in afko:
            print(f"    AUFNR={r['AUFNR']}  Material={r['PLNBEZ']}  Qty={r['GAMNG']}  "
                  f"Start={r['GSTRS']}  End={r['GLTRP']}")
    else:
        print("  (no production order details in AFKO)")


# ============================================================================
# Main
# ============================================================================

def main():
    print("=" * 70)
    print("SAP S4H Demo Data Creator")
    print("=" * 70)
    print(f"Host: {CONN_PARAMS['ashost']}, Instance: {CONN_PARAMS['sysnr']}, "
          f"Client: {CONN_PARAMS['client']}")
    print()

    with RFCConnection(**CONN_PARAMS) as conn:
        print("[+] RFC connection established\n")

        # Phase 1: Query config
        config = query_config(conn)

        # Phase 2: Create sales orders
        sales_orders = create_sales_orders(conn, config)

        # Phase 3: Try billing
        billing_docs = create_billing_documents(conn, sales_orders)

        # Phase 4: Create production orders
        prod_orders = create_production_orders(conn, config)

        # Phase 5: Verify
        verify_data(conn, sales_orders, billing_docs, prod_orders)

        # Summary
        print("\n" + "=" * 70)
        print("SUMMARY")
        print("=" * 70)
        print(f"  Sales orders created:      {len(sales_orders)}")
        if sales_orders:
            print(f"    Numbers: {', '.join(sales_orders)}")
        print(f"  Billing docs created:      {len(billing_docs)}")
        if billing_docs:
            print(f"    Numbers: {', '.join(billing_docs)}")
        print(f"  Production orders created: {len(prod_orders)}")
        if prod_orders:
            print(f"    Numbers: {', '.join(prod_orders)}")
        print()


if __name__ == '__main__':
    main()
