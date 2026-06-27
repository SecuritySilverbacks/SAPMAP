#!/usr/bin/env python3
"""
Final verification and additional data creation.

Discovered: VBAK already has 10 sales orders (type OR) with EUR 1.2M total value!
"""
import sys
sys.path.insert(0, '/home/joris/Desktop/CLAUDE/SAPMAP')
from sap_rfc_ctypes import RFCConnection

SDK = '/home/joris/Desktop/nwrfc750P_18-70002752/nwrfcsdk/lib/libsapnwrfc.so'
CONN_PARAMS = dict(
    sdk_path=SDK, ashost='192.168.2.209', sysnr='00',
    client='001', user='joris', passwd='Schaap123!', lang='EN',
)

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

VKORG = '0001'
VTWEG = '01'
SPART = '01'
PLANT = '0001'


def main():
    with RFCConnection(**CONN_PARAMS) as conn:
        print("[+] RFC connected\n")

        # ================================================================
        # Full verification of all data
        # ================================================================
        print("=" * 60)
        print("COMPREHENSIVE DATA VERIFICATION")
        print("=" * 60)

        # 1. Sales Orders
        print("\n[1] SALES ORDERS (VBAK)")
        vbak = read_table(conn, 'VBAK',
            ['VBELN', 'AUART', 'VKORG', 'VTWEG', 'SPART', 'KUNNR', 'NETWR', 'WAERK', 'ERDAT'],
            max_rows=30)
        total_so_value = 0
        print(f"  Count: {len(vbak)}")
        for r in vbak:
            try:
                val = float(r['NETWR'].replace(',', ''))
                total_so_value += val
            except:
                val = 0
            print(f"  {r['VBELN']} | {r['AUART']} | Org={r['VKORG']}/{r['VTWEG']}/{r['SPART']} | "
                  f"Cust={r['KUNNR']} | Net={r['NETWR']} {r['WAERK']} | Created={r['ERDAT']}")
        print(f"  TOTAL VALUE: {total_so_value:,.2f} EUR")

        # 2. Sales Order Items
        print("\n[2] SALES ORDER ITEMS (VBAP)")
        vbap = read_table(conn, 'VBAP',
            ['VBELN', 'POSNR', 'MATNR', 'KWMENG', 'VRKME', 'NETWR'],
            max_rows=30)
        print(f"  Count: {len(vbap)}")
        for r in vbap:
            print(f"  {r['VBELN']}/{r['POSNR']} | Mat={r['MATNR']} | Qty={r['KWMENG']} {r['VRKME']} | Net={r['NETWR']}")

        # 3. Production Orders
        print("\n[3] PRODUCTION ORDERS (AUFK)")
        aufk = read_table(conn, 'AUFK',
            ['AUFNR', 'AUART', 'AUTYP', 'ERDAT', 'AEDAT', 'LOEKZ'],
            max_rows=20)
        print(f"  Count: {len(aufk)}")
        for r in aufk:
            print(f"  {r['AUFNR']} | Type={r['AUART']} | Cat={r['AUTYP']} | "
                  f"Created={r['ERDAT']} | DelFlag={r['LOEKZ']}")

        # 4. Production Order Details
        print("\n[4] PRODUCTION ORDER DETAILS (AFKO)")
        afko = read_table(conn, 'AFKO',
            ['AUFNR', 'PLNBEZ', 'GAMNG', 'GSTRS', 'GLTRP'],
            max_rows=20)
        print(f"  Count: {len(afko)}")
        for r in afko:
            print(f"  {r['AUFNR']} | Material={r['PLNBEZ']} | Qty={r['GAMNG']} | "
                  f"Start={r['GSTRS']} | End={r['GLTRP']}")

        # 5. Planned Orders
        print("\n[5] PLANNED ORDERS (PLAF)")
        plaf = read_table(conn, 'PLAF',
            ['PLNUM', 'MATNR', 'PLWRK', 'GSMNG', 'PSTTR', 'PEDTR', 'PLART'],
            max_rows=20)
        print(f"  Count: {len(plaf)}")
        for r in plaf:
            print(f"  {r['PLNUM']} | Mat={r['MATNR']} | Plant={r['PLWRK']} | "
                  f"Qty={r['GSMNG']} | Start={r['PSTTR']} | Type={r['PLART']}")

        # 6. Materials
        print("\n[6] MATERIALS (MARA)")
        mara = read_table(conn, 'MARA', ['MATNR', 'MTART'], max_rows=40)
        hawa_count = sum(1 for r in mara if r['MTART'] == 'HAWA')
        fert_count = sum(1 for r in mara if r['MTART'] == 'FERT')
        print(f"  Total: {len(mara)} (HAWA={hawa_count}, FERT={fert_count})")

        # 7. Material Sales Views
        print("\n[7] MATERIAL SALES VIEWS (MVKE)")
        mvke = read_table(conn, 'MVKE', ['MATNR', 'VKORG', 'VTWEG'], max_rows=30)
        print(f"  Count: {len(mvke)}")

        # 8. Material Plant Data
        print("\n[8] MATERIAL PLANT DATA (MARC)")
        marc = read_table(conn, 'MARC', ['MATNR', 'WERKS', 'BESKZ', 'DISMM'], max_rows=30)
        print(f"  Count: {len(marc)}")
        for r in marc:
            print(f"  {r['MATNR']} | Plant={r['WERKS']} | Proc={r['BESKZ']} | MRP={r['DISMM']}")

        # 9. Customers
        print("\n[9] CUSTOMERS (KNA1)")
        kna1 = read_table(conn, 'KNA1', ['KUNNR', 'NAME1', 'KTOKD', 'ORT01'], max_rows=30)
        print(f"  Count: {len(kna1)}")
        for r in kna1:
            print(f"  {r['KUNNR']} | {r['NAME1']} | Group={r['KTOKD']} | City={r['ORT01']}")

        # 10. Customer Company Code
        print("\n[10] CUSTOMER COMPANY CODE (KNB1)")
        knb1 = read_table(conn, 'KNB1', ['KUNNR', 'BUKRS', 'AKONT'], max_rows=30)
        print(f"  Count: {len(knb1)}")
        for r in knb1:
            print(f"  {r['KUNNR']} | Company={r['BUKRS']} | Recon={r['AKONT']}")

        # 11. Customer Sales Area
        print("\n[11] CUSTOMER SALES AREA (KNVV)")
        knvv = read_table(conn, 'KNVV', ['KUNNR', 'VKORG', 'VTWEG', 'SPART'], max_rows=20)
        print(f"  Count: {len(knvv)}")
        for r in knvv:
            print(f"  {r}")

        # 12. Billing Documents
        print("\n[12] BILLING DOCUMENTS (VBRK)")
        vbrk = read_table(conn, 'VBRK', ['VBELN', 'FKART', 'NETWR', 'WAERK'], max_rows=20)
        print(f"  Count: {len(vbrk)}")
        for r in vbrk:
            print(f"  {r}")

        # 13. Vendors
        print("\n[13] VENDORS (LFA1)")
        lfa1 = read_table(conn, 'LFA1', ['LIFNR', 'NAME1'], max_rows=30)
        print(f"  Count: {len(lfa1)}")

        # ================================================================
        # Create additional planned/production orders
        # ================================================================
        print("\n" + "=" * 60)
        print("CREATE ADDITIONAL PRODUCTION DATA")
        print("=" * 60)

        # More planned orders with different materials
        materials_planned = [f'Z_SAPMAP_M{i:04d}' for i in range(6, 11)]
        created_more_planned = []

        for idx, mat in enumerate(materials_planned):
            qty = [150, 300, 750, 1500, 3000][idx]
            print(f"\n  Planned Order: Mat={mat}, Qty={qty}")
            try:
                r = conn.call('BAPI_PLANNEDORDER_CREATE',
                    HEADERDATA={
                        'MATERIAL': mat,
                        'PLAN_PLANT': PLANT,
                        'PROD_PLANT': PLANT,
                        'TOTAL_PLORD_QTY': str(qty),
                        'PLAN_OPEN_DATE': '20260420',
                        'ORDER_FIN_DATE': '20260510',
                        'PLDORD_PROFILE': 'NB',
                    },
                )
                po_num = (r.get('PLANNEDORDER', '') or '').strip()
                if po_num:
                    print(f"    [OK] Planned order: {po_num}")
                    commit(conn)
                    created_more_planned.append(po_num)
                else:
                    ret = r.get('RETURN', {})
                    msg = ret.get('MESSAGE', '') if isinstance(ret, dict) else ''
                    print(f"    [FAIL] {msg}")
                    rollback(conn)
            except Exception as e:
                print(f"    Error: {e}")
                rollback(conn)

        print(f"\n  Additional planned orders: {len(created_more_planned)}")

        # More production orders
        prod_mats = [f'Z_SAPMAP_P{i:04d}' for i in range(1, 6)]
        created_more_prod = []

        for idx, mat in enumerate(prod_mats):
            qty = [500, 750, 1500, 3000, 5000][idx]
            print(f"\n  Prod Order: Mat={mat}, Qty={qty}")
            try:
                r = conn.call('BAPI_PRODORD_CREATE',
                    ORDERDATA={
                        'MATERIAL': mat,
                        'PLANT': PLANT,
                        'ORDER_TYPE': 'PP01',
                        'QUANTITY': str(qty),
                        'BASIC_START_DATE': '20260501',
                        'BASIC_END_DATE': '20260531',
                    },
                )
                order_num = (r.get('ORDER_NUMBER', '') or '').strip()
                ret = r.get('RETURN', [])
                if order_num:
                    print(f"    [OK] Order: {order_num}")
                    commit(conn)
                    created_more_prod.append(order_num)
                else:
                    for m in (ret if isinstance(ret, list) else [ret]):
                        if isinstance(m, dict) and m.get('TYPE') in ('E', 'A'):
                            print(f"    [{m['TYPE']}] {m.get('MESSAGE','')}")
                    rollback(conn)
            except Exception as e:
                print(f"    Error: {e}")
                rollback(conn)

        print(f"\n  Additional production orders: {len(created_more_prod)}")

        # ================================================================
        # FINAL SUMMARY
        # ================================================================
        print("\n" + "=" * 60)
        print("FINAL SUMMARY OF ALL DATA")
        print("=" * 60)

        vbak_f = read_table(conn, 'VBAK', ['VBELN', 'NETWR'], max_rows=30)
        aufk_f = read_table(conn, 'AUFK', ['AUFNR'], max_rows=30)
        plaf_f = read_table(conn, 'PLAF', ['PLNUM'], max_rows=30)
        afko_f = read_table(conn, 'AFKO', ['AUFNR', 'PLNBEZ', 'GAMNG'], max_rows=30)
        mvke_f = read_table(conn, 'MVKE', ['MATNR'], max_rows=30)
        marc_f = read_table(conn, 'MARC', ['MATNR'], max_rows=30)
        mara_f = read_table(conn, 'MARA', ['MATNR', 'MTART'], max_rows=40)

        total_val = sum(float(r['NETWR'].replace(',', '')) for r in vbak_f if r.get('NETWR'))
        total_prod_qty = sum(float(r['GAMNG'].replace(',', '')) for r in afko_f if r.get('GAMNG'))

        print(f"""
  Revenue Dashboard Scenario:
  ---------------------------
    Sales Orders (VBAK):        {len(vbak_f)} orders
    Total Order Value:          EUR {total_val:,.2f}
    Material Sales Views:       {len(mvke_f)} entries
    Customers (KNA1):           {len(kna1)} customers

  Production Sabotage Scenario:
  -----------------------------
    Production Orders (AUFK):   {len(aufk_f)} orders
    Production Details (AFKO):  {len(afko_f)} entries
    Total Prod Quantity:        {total_prod_qty:,.0f} units
    Planned Orders (PLAF):      {len(plaf_f)} orders
    FERT Materials:             {sum(1 for r in mara_f if r.get('MTART') == 'FERT')}
    HAWA Materials:             {sum(1 for r in mara_f if r.get('MTART') == 'HAWA')}
    Plant-Material (MARC):      {len(marc_f)} entries

  Master Data:
  ------------
    Total Materials (MARA):     {len(mara_f)}
    Total Customers (KNA1):     {len(kna1)}
    Vendors (LFA1):             {len(lfa1)}
""")


if __name__ == '__main__':
    main()
