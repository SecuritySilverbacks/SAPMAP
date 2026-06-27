#!/usr/bin/env python3
"""
Create demo data in S4H — Final script.

Confirmed config:
- Sales org: 0001, dist channel: 01, division: 01
- Company code: 0001 (SAP SE, EUR)
- Plant: 0001
- 10 customers in KNA1, company code data in KNB1 (AKONT=142000)
- 25 materials HAWA type, 10 with plant data (BESKZ=F = external procurement)
- MVKE has one entry (Z_SAPMAP_M0001 in 0001/01) from earlier test
- KNVV is empty — customers have no sales area assignment
- BESKZ='F' prevents production orders — need 'E' (in-house)

Plan:
1. Extend all materials with sales views (MVKE) using BAPI_MATERIAL_SAVEDATA
2. Change procurement type from F to E for production scenario
3. Extend customers to sales area using BAPI_CUSTOMER_CREATEFROMDATA1
4. Create sales orders
5. Create production orders (after BESKZ change)
6. Verify
"""
import sys
import traceback

sys.path.insert(0, '/home/joris/Desktop/CLAUDE/SAPMAP')
from sap_rfc_ctypes import RFCConnection

SDK = '/home/joris/Desktop/nwrfc750P_18-70002752/nwrfcsdk/lib/libsapnwrfc.so'
CONN_PARAMS = dict(
    sdk_path=SDK, ashost='192.168.2.209', sysnr='00',
    client='001', user='joris', passwd='Schaap123!', lang='EN',
)

VKORG = '0001'
VTWEG = '01'
SPART = '01'
PLANT = '0001'
BUKRS = '0001'


def read_table(conn, table, fields, max_rows=100, where=''):
    field_list = [{'FIELDNAME': f} for f in fields]
    kwargs = dict(QUERY_TABLE=table, DELIMITER='|', ROWCOUNT=max_rows, FIELDS=field_list)
    if where:
        kwargs['OPTIONS'] = [{'TEXT': where}]
    try:
        result = conn.call('RFC_READ_TABLE', **kwargs)
    except Exception as e:
        print(f"  [ERROR] {table}: {e}")
        return []
    rows = []
    for row in result.get('DATA', []):
        wa = row.get('WA', '')
        vals = wa.split('|')
        d = {}
        for i, f in enumerate(fields):
            d[f] = vals[i].strip() if i < len(vals) else ''
        rows.append(d)
    return rows


def commit(conn):
    try:
        return conn.call('BAPI_TRANSACTION_COMMIT', WAIT='X')
    except Exception as e:
        print(f"  [COMMIT ERROR] {e}")
        return {}


def rollback(conn):
    try:
        conn.call('BAPI_TRANSACTION_ROLLBACK')
    except Exception:
        pass


def print_ret(ret):
    if isinstance(ret, dict):
        ret = [ret]
    for msg in ret:
        if isinstance(msg, dict):
            t = msg.get('TYPE', '?')
            text = msg.get('MESSAGE', '')
            if text:
                print(f"    [{t}] {text}")


def has_err(ret):
    if isinstance(ret, dict):
        return ret.get('TYPE') in ('E', 'A')
    if isinstance(ret, list):
        return any(isinstance(m, dict) and m.get('TYPE') in ('E', 'A') for m in ret)
    return False


def main():
    with RFCConnection(**CONN_PARAMS) as conn:
        print("[+] RFC connected\n")

        # ================================================================
        # STEP 1: Extend materials with sales views
        # ================================================================
        print("=" * 60)
        print("STEP 1: Create material sales views (MVKE)")
        print("=" * 60)

        materials = [f'Z_SAPMAP_M{i:04d}' for i in range(1, 26)]
        mat_success = []

        for mat in materials:
            print(f"\n  Extending {mat} with sales view...")
            try:
                r = conn.call('BAPI_MATERIAL_SAVEDATA',
                    HEADDATA={
                        'MATERIAL': mat,
                        'SALES_VIEW': 'X',
                    },
                    SALESDATA={
                        'SALES_ORG': VKORG,
                        'DISTR_CHAN': VTWEG,
                        'BASE_UOM': 'ST',
                    },
                    SALESDATAX={
                        'SALES_ORG': VKORG,
                        'DISTR_CHAN': VTWEG,
                        'BASE_UOM': 'X',
                    },
                    TAXCLASSIFICATIONS=[
                        {
                            'DEPCOUNTRY': 'DE',
                            'TAX_TYPE_1': 'MWST',
                            'TAXCLASS_1': '1',
                        },
                    ],
                )
                ret = r.get('RETURN', {})
                rmsg = r.get('RETURNMESSAGES', [])
                if has_err(ret):
                    print_ret(ret if isinstance(ret, list) else [ret])
                    if rmsg:
                        print_ret(rmsg)
                    rollback(conn)
                else:
                    commit(conn)
                    mat_success.append(mat)
                    ret_text = ret.get('MESSAGE', '') if isinstance(ret, dict) else ''
                    print(f"    [OK] {ret_text}")
            except Exception as e:
                print(f"    [ERROR] {e}")
                rollback(conn)

        print(f"\n  Materials with sales views: {len(mat_success)}/{len(materials)}")

        # Verify MVKE
        print("\n  Verifying MVKE...")
        mvke = read_table(conn, 'MVKE', ['MATNR', 'VKORG', 'VTWEG'], max_rows=30)
        print(f"  MVKE entries: {len(mvke)}")
        for r in mvke[:5]:
            print(f"    {r}")

        # ================================================================
        # STEP 2: Change procurement type for production
        # ================================================================
        print("\n" + "=" * 60)
        print("STEP 2: Change procurement type (BESKZ) to E (in-house)")
        print("=" * 60)

        prod_materials = [f'Z_SAPMAP_M{i:04d}' for i in range(1, 6)]
        prod_success = []

        for mat in prod_materials:
            print(f"\n  Changing {mat} procurement type to E...")
            try:
                r = conn.call('BAPI_MATERIAL_SAVEDATA',
                    HEADDATA={
                        'MATERIAL': mat,
                        'MRP_VIEW': 'X',
                    },
                    PLANTDATA={
                        'PLANT': PLANT,
                        'AVAILCHECK': '02',
                        'PROC_TYPE': 'E',  # In-house production
                    },
                    PLANTDATAX={
                        'PLANT': PLANT,
                        'AVAILCHECK': 'X',
                        'PROC_TYPE': 'X',
                    },
                )
                ret = r.get('RETURN', {})
                if has_err(ret):
                    print_ret(ret if isinstance(ret, list) else [ret])
                    rmsg = r.get('RETURNMESSAGES', [])
                    if rmsg:
                        print_ret(rmsg)
                    rollback(conn)
                else:
                    commit(conn)
                    prod_success.append(mat)
                    ret_text = ret.get('MESSAGE', '') if isinstance(ret, dict) else ''
                    print(f"    [OK] {ret_text}")
            except Exception as e:
                print(f"    [ERROR] {e}")
                rollback(conn)

        print(f"\n  Materials with in-house procurement: {len(prod_success)}/{len(prod_materials)}")

        # Verify
        marc_check = read_table(conn, 'MARC', ['MATNR', 'WERKS', 'BESKZ'],
                               max_rows=10, where="MATNR LIKE 'Z_SAPMAP_M000%'")
        for r in marc_check:
            print(f"    {r}")

        # ================================================================
        # STEP 3: Extend customers to sales area
        # ================================================================
        print("\n" + "=" * 60)
        print("STEP 3: Extend customers to sales area")
        print("=" * 60)

        customer_data = [
            ('0000000001', 'Mueller Retail AG', 'DE'),
            ('0000000002', 'Schmidt und Soehne KG', 'DE'),
            ('0000000003', 'Weber Electronics GmbH', 'DE'),
            ('0000000004', 'Fischer Automotive GmbH', 'DE'),
            ('0000000005', 'Bauer Construction AG', 'DE'),
            ('0000000006', 'Schneider Pharma GmbH', 'DE'),
            ('0000000007', 'Hoffmann Logistics SE', 'DE'),
            ('0000000008', 'Wagner IT Services AG', 'DE'),
            ('0000000009', 'Koch Food Trading GmbH', 'DE'),
            ('0000000010', 'Becker Medical Devices AG', 'DE'),
        ]

        cust_success = []

        # BAPI_CUSTOMER_CREATEFROMDATA1 parameters:
        # PI_PERSONALDATA (BAPIKNA101_1): COUNTRY, CURRENCY, LANGU_P, etc.
        # PI_COPYREFERENCE (BAPIKNA102): SALESORG, DISTR_CHAN, DIVISION
        # PI_COMPANYDATA (BAPIKNA106): COUNTRY, LANGU, CURRENCY, NAME
        # PI_OPT_PERSONALDATA/PI_OPT_COMPANYDATA (BAPIKNA105): PMNTTRMS, CONTROL_ACCOUNT, etc.

        for cust_nr, name, country in customer_data:
            print(f"\n  Extending customer {cust_nr} ({name}) to sales area...")
            try:
                r = conn.call('BAPI_CUSTOMER_CREATEFROMDATA1',
                    PI_PERSONALDATA={
                        'FIRSTNAME': '',
                        'LASTNAME': name,
                        'COUNTRY': country,
                        'LANGU_P': 'E',
                        'CURRENCY': 'EUR',
                    },
                    PI_COPYREFERENCE={
                        'SALESORG': VKORG,
                        'DISTR_CHAN': VTWEG,
                        'DIVISION': SPART,
                    },
                    PI_COMPANYDATA={
                        'NAME': name,
                        'COUNTRY': country,
                        'LANGU': 'E',
                        'CURRENCY': 'EUR',
                    },
                    PI_OPT_PERSONALDATA={
                        'PMNTTRMS': '0001',
                        'CONTROL_ACCOUNT': '0000142000',
                    },
                )
                ret = r.get('RETURN', {})
                cust_out = r.get('CUSTOMERNO', '')
                print(f"    CUSTOMERNO returned: '{cust_out}'")

                if isinstance(ret, dict):
                    ret_type = ret.get('TYPE', '')
                    ret_msg = ret.get('MESSAGE', '')
                    print(f"    [{ret_type}] {ret_msg}")
                    if ret_type in ('E', 'A'):
                        rollback(conn)
                    else:
                        commit(conn)
                        cust_success.append(cust_out.strip() if cust_out else cust_nr)
                elif isinstance(ret, list):
                    print_ret(ret)
                    if has_err(ret):
                        rollback(conn)
                    else:
                        commit(conn)
                        cust_success.append(cust_out.strip() if cust_out else cust_nr)
                else:
                    commit(conn)
                    cust_success.append(cust_out.strip() if cust_out else cust_nr)

            except Exception as e:
                print(f"    [ERROR] {e}")
                rollback(conn)

        print(f"\n  Customers extended: {len(cust_success)}/{len(customer_data)}")

        # Verify KNVV
        print("\n  Verifying KNVV...")
        knvv = read_table(conn, 'KNVV', ['KUNNR', 'VKORG', 'VTWEG', 'SPART', 'WAERS'], max_rows=20)
        print(f"  KNVV entries: {len(knvv)}")
        for r in knvv:
            print(f"    {r}")

        # ================================================================
        # STEP 4: Create Sales Orders
        # ================================================================
        print("\n" + "=" * 60)
        print("STEP 4: Create Sales Orders")
        print("=" * 60)

        # Check which customers are in KNVV
        available_customers = [r['KUNNR'] for r in knvv] if knvv else cust_success
        available_materials = [r['MATNR'] for r in mvke] if mvke else mat_success

        if not available_customers:
            print("\n  [!] No customers with sales area. Trying with original customer numbers...")
            available_customers = [c[0] for c in customer_data]

        if not available_materials:
            print("\n  [!] No materials with sales views. Using material list...")
            available_materials = materials[:10]

        print(f"\n  Using customers: {available_customers[:5]}")
        print(f"  Using materials: {available_materials[:5]}")

        # Order specifications
        order_specs = [
            # (customer_idx, material_idx, qty, description)
            (0, 0, 50, 'Standard order - Mueller/M0001'),
            (1, 1, 100, 'Bulk order - Schmidt/M0002'),
            (2, 2, 25, 'Small order - Weber/M0003'),
            (3, 3, 200, 'Large order - Fischer/M0004'),
            (4, 4, 75, 'Medium order - Bauer/M0005'),
            (0, 5, 150, 'Repeat order - Mueller/M0006'),
            (1, 6, 30, 'Trial order - Schmidt/M0007'),
            (2, 7, 500, 'Volume order - Weber/M0008'),
            (3, 8, 10, 'Sample order - Fischer/M0009'),
            (4, 9, 1000, 'Framework order - Bauer/M0010'),
            (5, 0, 60, 'Pharma order - Schneider/M0001'),
            (6, 1, 300, 'Logistics order - Hoffmann/M0002'),
            (7, 2, 80, 'IT order - Wagner/M0003'),
            (8, 3, 120, 'Food order - Koch/M0004'),
            (9, 4, 45, 'Medical order - Becker/M0005'),
        ]

        created_orders = []

        for idx, (ci, mi, qty, desc) in enumerate(order_specs):
            cust = available_customers[ci % len(available_customers)]
            mat = available_materials[mi % len(available_materials)]
            print(f"\n  Order {idx+1}: {desc}")
            print(f"    Customer={cust}, Material={mat}, Qty={qty}")

            try:
                r = conn.call(
                    'BAPI_SALESORDER_CREATEFROMDAT2',
                    ORDER_HEADER_IN={
                        'DOC_TYPE': 'TA',
                        'SALES_ORG': VKORG,
                        'DISTR_CHAN': VTWEG,
                        'DIVISION': SPART,
                        'PURCH_NO_C': f'SAPMAP-{idx+1:03d}',
                    },
                    ORDER_PARTNERS=[
                        {'PARTN_ROLE': 'AG', 'PARTN_NMBR': cust},
                    ],
                    ORDER_ITEMS_IN=[
                        {
                            'ITM_NUMBER': '000010',
                            'MATERIAL': mat,
                            'TARGET_QTY': str(qty),
                            'TARGET_QU': 'ST',
                        },
                    ],
                    ORDER_SCHEDULES_IN=[
                        {
                            'ITM_NUMBER': '000010',
                            'SCHED_LINE': '0001',
                            'REQ_QTY': str(qty),
                        },
                    ],
                    ORDER_CONDITIONS_IN=[
                        {
                            'ITM_NUMBER': '000010',
                            'COND_TYPE': 'PR00',
                            'COND_VALUE': str(500 + idx * 200),
                            'CURRENCY': 'EUR',
                        },
                    ],
                )

                doc = (r.get('SALESDOCUMENT', '') or '').strip()
                ret = r.get('RETURN', [])

                if doc and doc != '0000000000':
                    print(f"    [OK] Sales order: {doc}")
                    commit(conn)
                    created_orders.append(doc)
                else:
                    print(f"    [FAIL]")
                    print_ret(ret)
                    rollback(conn)

                    # On first failure, try without conditions
                    if idx == 0:
                        print("\n    Retrying without pricing conditions...")
                        try:
                            r2 = conn.call(
                                'BAPI_SALESORDER_CREATEFROMDAT2',
                                ORDER_HEADER_IN={
                                    'DOC_TYPE': 'TA',
                                    'SALES_ORG': VKORG,
                                    'DISTR_CHAN': VTWEG,
                                    'DIVISION': SPART,
                                    'PURCH_NO_C': f'SAPMAP-{idx+1:03d}',
                                },
                                ORDER_PARTNERS=[
                                    {'PARTN_ROLE': 'AG', 'PARTN_NMBR': cust},
                                ],
                                ORDER_ITEMS_IN=[
                                    {'ITM_NUMBER': '000010', 'MATERIAL': mat,
                                     'TARGET_QTY': str(qty), 'TARGET_QU': 'ST'},
                                ],
                                ORDER_SCHEDULES_IN=[
                                    {'ITM_NUMBER': '000010', 'SCHED_LINE': '0001',
                                     'REQ_QTY': str(qty)},
                                ],
                            )
                            doc2 = (r2.get('SALESDOCUMENT', '') or '').strip()
                            ret2 = r2.get('RETURN', [])
                            if doc2 and doc2 != '0000000000':
                                print(f"    [OK] Sales order (no cond): {doc2}")
                                commit(conn)
                                created_orders.append(doc2)
                            else:
                                print(f"    [FAIL] Still no doc")
                                print_ret(ret2)
                                rollback(conn)
                        except Exception as e2:
                            print(f"    [ERROR] {e2}")
                            rollback(conn)

            except Exception as e:
                print(f"    [ERROR] {e}")
                rollback(conn)

            # If first 2 orders fail, stop trying
            if idx == 1 and not created_orders:
                print("\n  [!] First 2 orders failed. Stopping sales order creation.")
                break

        print(f"\n  Sales orders created: {len(created_orders)}")

        # ================================================================
        # STEP 5: Create Production Orders
        # ================================================================
        print("\n" + "=" * 60)
        print("STEP 5: Create Production Orders")
        print("=" * 60)

        # Re-check procurement type
        marc_check2 = read_table(conn, 'MARC', ['MATNR', 'WERKS', 'BESKZ'],
                                max_rows=10, where="MATNR LIKE 'Z_SAPMAP_M000%'")
        in_house_mats = [r['MATNR'] for r in marc_check2 if r.get('BESKZ') == 'E']
        print(f"\n  Materials with in-house procurement: {in_house_mats}")

        if not in_house_mats:
            print("  [!] No in-house materials. Trying production orders anyway...")
            in_house_mats = [f'Z_SAPMAP_M{i:04d}' for i in range(1, 6)]

        created_prod = []

        for idx, mat in enumerate(in_house_mats[:5]):
            qty = [100, 250, 500, 1000, 2000][idx % 5]
            print(f"\n  Prod Order {idx+1}: Material={mat}, Plant={PLANT}, Qty={qty}")

            try:
                r = conn.call('BAPI_PRODORD_CREATE',
                    ORDERDATA={
                        'MATERIAL': mat,
                        'PLANT': PLANT,
                        'ORDER_TYPE': 'PP01',
                        'QUANTITY': str(qty),
                        'BASIC_START_DATE': '20260415',
                        'BASIC_END_DATE': '20260430',
                    },
                )
                order_num = (r.get('ORDER_NUMBER', '') or '').strip()
                ret = r.get('RETURN', [])

                if order_num:
                    print(f"    [OK] Production order: {order_num}")
                    commit(conn)
                    created_prod.append(order_num)
                else:
                    print(f"    [FAIL]")
                    print_ret(ret)
                    rollback(conn)
            except Exception as e:
                print(f"    [ERROR] {e}")
                rollback(conn)

            # If first fails, try planned orders
            if idx == 0 and not created_prod:
                print("\n  [*] Trying planned orders as fallback...")
                for pidx, pmat in enumerate(in_house_mats[:5]):
                    pqty = [100, 250, 500, 1000, 2000][pidx % 5]
                    print(f"\n  Planned Order {pidx+1}: Material={pmat}, Qty={pqty}")
                    try:
                        r2 = conn.call('BAPI_PLANNEDORDER_CREATE',
                            HEADERDATA={
                                'MATERIAL': pmat,
                                'PLANT': PLANT,
                                'TOTAL_PLORD_QTY': str(pqty),
                                'PLAN_OPEN_DATE': '20260415',
                                'ORDER_FIN_DATE': '20260430',
                            },
                        )
                        po_num = (r2.get('PLANNEDORDER', '') or '').strip()
                        ret2 = r2.get('RETURN', {})
                        if po_num:
                            print(f"    [OK] Planned order: {po_num}")
                            commit(conn)
                            created_prod.append(po_num)
                        else:
                            print(f"    [FAIL]")
                            if isinstance(ret2, dict):
                                print(f"    [{ret2.get('TYPE','')}] {ret2.get('MESSAGE','')}")
                            else:
                                print_ret(ret2)
                            rollback(conn)
                    except Exception as e2:
                        print(f"    [ERROR] {e2}")
                        rollback(conn)
                break  # Don't try more prod orders if PP01 fails

        print(f"\n  Production/planned orders created: {len(created_prod)}")

        # ================================================================
        # STEP 6: Verification
        # ================================================================
        print("\n" + "=" * 60)
        print("STEP 6: Verify All Created Data")
        print("=" * 60)

        # VBAK
        print("\n[6a] Sales Orders (VBAK):")
        vbak = read_table(conn, 'VBAK', ['VBELN', 'AUART', 'VKORG', 'KUNNR', 'NETWR', 'WAERK'],
                         max_rows=30)
        if vbak:
            total_value = 0
            for r in vbak:
                print(f"  {r['VBELN']}  Type={r['AUART']}  Org={r['VKORG']}  "
                      f"Cust={r['KUNNR']}  Net={r['NETWR']} {r['WAERK']}")
                try:
                    total_value += float(r['NETWR'].replace(',', ''))
                except:
                    pass
            print(f"\n  Total: {len(vbak)} orders, total value: {total_value:.2f}")
        else:
            print("  (none)")

        # VBAP
        print("\n[6b] Sales Order Items (VBAP):")
        vbap = read_table(conn, 'VBAP', ['VBELN', 'POSNR', 'MATNR', 'KWMENG', 'NETWR'],
                         max_rows=30)
        if vbap:
            for r in vbap[:10]:
                print(f"  {r['VBELN']}/{r['POSNR']}  Mat={r['MATNR']}  Qty={r['KWMENG']}  "
                      f"Net={r['NETWR']}")
        else:
            print("  (none)")

        # AUFK / AFKO
        print("\n[6c] Production/Internal Orders (AUFK):")
        aufk = read_table(conn, 'AUFK', ['AUFNR', 'AUART', 'AUTYP', 'ERDAT'],
                         max_rows=20)
        if aufk:
            for r in aufk:
                print(f"  {r['AUFNR']}  Type={r['AUART']}  Cat={r['AUTYP']}  Created={r['ERDAT']}")
        else:
            print("  (none)")

        # PLAF (planned orders)
        print("\n[6d] Planned Orders (PLAF):")
        plaf = read_table(conn, 'PLAF', ['PLNUM', 'MATNR', 'PLWRK', 'GSMNG', 'PSTTR'],
                         max_rows=20)
        if plaf:
            for r in plaf:
                print(f"  {r['PLNUM']}  Mat={r['MATNR']}  Plant={r['PLWRK']}  "
                      f"Qty={r['GSMNG']}  Start={r['PSTTR']}")
        else:
            print("  (none)")

        # KNVV
        print("\n[6e] Customer Sales Area (KNVV):")
        knvv2 = read_table(conn, 'KNVV', ['KUNNR', 'VKORG', 'VTWEG', 'SPART'], max_rows=20)
        if knvv2:
            for r in knvv2:
                print(f"  {r}")
        else:
            print("  (still empty)")

        # MVKE
        print("\n[6f] Material Sales Views (MVKE):")
        mvke2 = read_table(conn, 'MVKE', ['MATNR', 'VKORG', 'VTWEG'], max_rows=30)
        print(f"  Total entries: {len(mvke2)}")

        # ================================================================
        # Summary
        # ================================================================
        print("\n" + "=" * 60)
        print("SUMMARY")
        print("=" * 60)
        print(f"  Materials with sales views (MVKE): {len(mvke2)}")
        print(f"  Customers with sales area (KNVV): {len(knvv2)}")
        print(f"  Sales orders created (VBAK):      {len(created_orders)}")
        if created_orders:
            print(f"    Numbers: {', '.join(created_orders)}")
        print(f"  Production/planned orders:         {len(created_prod)}")
        if created_prod:
            print(f"    Numbers: {', '.join(created_prod)}")


if __name__ == '__main__':
    main()
