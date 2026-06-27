#!/usr/bin/env python3
"""
Double the demo data in S4H system for all 8 business impact scenarios.

Approach per table:
  1. Try BAPI (cleanest)
  2. If BAPI fails, fall back to direct HANA INSERT via SXPG_STEP_XPG_START + hdbsql

Skips: USR02/AGR_USERS (already 46 users — plenty)
"""
import sys
import time
import traceback
import base64

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

HDBSQL = '/usr/sap/S4H/hdbclient/hdbsql'

# ============================================================================
# Utility functions
# ============================================================================

def read_table(conn, table, fields, max_rows=200, where=''):
    field_list = [{'FIELDNAME': f} for f in fields]
    kwargs = dict(QUERY_TABLE=table, DELIMITER='|', ROWCOUNT=max_rows, FIELDS=field_list)
    if where:
        kwargs['OPTIONS'] = [{'TEXT': where}]
    try:
        result = conn.call('RFC_READ_TABLE', **kwargs)
    except Exception as e:
        print(f"  [ERROR] RFC_READ_TABLE on {table}: {e}")
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


def has_err(ret):
    if isinstance(ret, dict):
        return ret.get('TYPE') in ('E', 'A')
    if isinstance(ret, list):
        return any(isinstance(m, dict) and m.get('TYPE') in ('E', 'A') for m in ret)
    return False


def print_ret(ret):
    if isinstance(ret, dict):
        ret = [ret]
    for msg in ret:
        if isinstance(msg, dict):
            t = msg.get('TYPE', '?')
            text = msg.get('MESSAGE', '')
            if text:
                print(f"    [{t}] {text}")


SXPG_BASE = dict(TARGET="", DESTINATION="", STDINCNTL="R", STDOUTCNTL="M",
                 STDERRCNTL="M", TRACECNTL="0", TERMCNTL="C", TRACELEVEL="0",
                 LONG_PARAMS="", CONNCNTL="H")


def sxpg(conn, prog, params, label, long_params=None):
    """Execute OS command via SXPG_STEP_XPG_START and return log lines."""
    print(f"\n  [SXPG] {label}")
    kw = dict(SXPG_BASE, EXTPROG=prog, PARAMS=params)
    if long_params is not None:
        kw['LONG_PARAMS'] = long_params
    try:
        try:
            r = conn.call("SXPG_STEP_XPG_START", MXROW=9999, **kw)
        except Exception as e:
            if "MXROW" in str(e) or "RFC_INVALID" in str(e):
                r = conn.call("SXPG_STEP_XPG_START", **kw)
            else:
                print(f"    ERROR: {e}")
                return None
    except Exception as e:
        print(f"    ERROR: {e}")
        return None

    lines = []
    for row in r.get("LOG", []):
        line = (row.get("MESSAGE") or row.get("LINE") or row.get("TEXT") or "") \
               if isinstance(row, dict) else str(row)
        line = line.rstrip()
        if line:
            lines.append(line)
            print(f"    {line}")
    status = r.get('STATUS', '?')
    if not lines:
        print(f"    (no output, exit={status})")
    return lines


def hdbsql_exec_batch(conn, sql_statements, label):
    """Execute SQL statements via hdbsql using a two-step SXPG approach.

    hdbsql's argument parser chokes on single-quotes in LONG_PARAMS,
    so we: 1) write all SQL to /tmp/s.sql via python3 base64 decode,
           2) execute hdbsql -U DEFAULT -x -I /tmp/s.sql

    sql_statements: list of SQL strings (without trailing semicolons)
    """
    # Build the SQL file content
    sql_content = "\n".join(s.rstrip(";") + ";" for s in sql_statements) + "\n"
    b64data = base64.b64encode(sql_content.encode()).decode()

    # Step 1: Write SQL file via python3 (no spaces in python script!)
    py_script = (
        f'b=__import__("base64");'
        f'f=open("/tmp/s.sql","w");'
        f'f.write(b.b64decode("{b64data}").decode());'
        f'f.close();'
        f'print("wrote_"+str(len(b.b64decode("{b64data}")))+"_bytes")'
    )

    # LONG_PARAMS max is ~1024. If py_script is too long, split into chunks.
    if len(py_script) > 1020:
        # Write b64 to a temp file first, then decode
        b64_file = "/tmp/s.b64"
        # Write b64 in chunks via multiple python3 calls
        chunk_size = 700  # safe chunk size for LONG_PARAMS
        chunks = [b64data[i:i+chunk_size] for i in range(0, len(b64data), chunk_size)]
        for ci, chunk in enumerate(chunks):
            mode = "w" if ci == 0 else "a"
            py_chunk = (
                f'f=open("{b64_file}","{mode}");'
                f'f.write("{chunk}");'
                f'f.close()'
            )
            sxpg(conn, '/usr/bin/python3', '-c', f'{label} write-b64 [{ci+1}/{len(chunks)}]',
                 long_params=py_chunk)

        # Now decode the b64 file to SQL file
        py_decode = (
            f'b=__import__("base64");'
            f'f=open("{b64_file}");d=f.read();f.close();'
            f'g=open("/tmp/s.sql","w");'
            f'g.write(b.b64decode(d).decode());'
            f'g.close();'
            f'print("decoded")'
        )
        sxpg(conn, '/usr/bin/python3', '-c', f'{label} decode-b64',
             long_params=py_decode)
    else:
        sxpg(conn, '/usr/bin/python3', '-c', f'{label} write-sql',
             long_params=py_script)

    # Step 2: Execute the SQL file
    result = sxpg(conn, HDBSQL, '-U DEFAULT -x -I /tmp/s.sql', f'{label} exec-sql')
    return result


def hdbsql_multi(conn, statements, label, batch_size=20):
    """Execute multiple SQL statements via hdbsql in batches."""
    results = []
    for i in range(0, len(statements), batch_size):
        batch = statements[i:i+batch_size]
        sub_label = f"{label} [batch {i//batch_size + 1}]"
        r = hdbsql_exec_batch(conn, batch, sub_label)
        results.append(r)
    return results


# ============================================================================
# Scenario 1: HR Data (PA0002 / PA0008)
# ============================================================================

def add_hr_data(conn):
    print("\n" + "=" * 70)
    print("SCENARIO 1: HR Employee Data (PA0002 / PA0008)")
    print("=" * 70)

    # Check existing
    pa0002 = read_table(conn, 'PA0002', ['PERNR', 'VORNA', 'NACHN'], max_rows=50)
    print(f"  Current PA0002 records: {len(pa0002)}")

    existing_pernrs = {r['PERNR'].lstrip('0') for r in pa0002}

    # New employees — 10 additional with realistic names
    new_employees = [
        ('00000101', 'Anna', 'Bergmann', 55000),
        ('00000102', 'Lars', 'Lindqvist', 72000),
        ('00000103', 'Sophie', 'Dubois', 88000),
        ('00000104', 'Pieter', 'de Groot', 64000),
        ('00000105', 'Maria', 'Gonzalez', 95000),
        ('00000106', 'Thomas', 'Eriksson', 48000),
        ('00000107', 'Claudia', 'Rossi', 110000),
        ('00000108', 'Jan', 'Kowalski', 53000),
        ('00000109', 'Elena', 'Popescu', 67000),
        ('00000110', 'Hans', 'Zimmermann', 120000),
    ]

    # Filter out any that already exist
    to_add = [(p, fn, ln, sal) for p, fn, ln, sal in new_employees
              if p.lstrip('0') not in existing_pernrs]
    print(f"  Employees to add: {len(to_add)}")

    if not to_add:
        print("  All employees already exist. Skipping.")
        return

    # Go straight to hdbsql (BAPI_HRMASTER_SAVE_REPL_MULT has complex interface)
    print("\n  Using hdbsql for direct INSERT into PA0002 and PA0008...")

    pa0002_stmts = []
    pa0008_stmts = []

    for pernr, fn, ln, sal in to_add:
        pa0002_stmts.append(
            f"INSERT INTO PA0002 "
            f"(MANDT, PERNR, SUBTY, OBJPS, SPRPS, ENDDA, BEGDA, SEQNR, "
            f"VORNA, NACHN, GESCH, GBDAT, GBLND, NATIO) "
            f"VALUES ('001', '{pernr}', '', '', '', '99991231', '19000101', '000', "
            f"'{fn}', '{ln}', '1', '19850115', 'DE', 'DE')"
        )
        pa0008_stmts.append(
            f"INSERT INTO PA0008 "
            f"(MANDT, PERNR, SUBTY, OBJPS, SPRPS, ENDDA, BEGDA, SEQNR, "
            f"TRFAR, TRFGB, TRFGR, TRFST, ANSAL, WAERS, DIVGV, BSGRD) "
            f"VALUES ('001', '{pernr}', '', '', '', '99991231', '19000101', '000', "
            f"'01', '01', '01', '01', '{sal:.2f}', 'EUR', '0.00', '100.00')"
        )

    print(f"\n  Inserting {len(pa0002_stmts)} PA0002 records...")
    hdbsql_multi(conn, pa0002_stmts, "PA0002 INSERT")

    print(f"\n  Inserting {len(pa0008_stmts)} PA0008 records...")
    hdbsql_multi(conn, pa0008_stmts, "PA0008 INSERT")

    # Verify
    pa0002_after = read_table(conn, 'PA0002', ['PERNR', 'VORNA', 'NACHN'], max_rows=50)
    pa0008_after = read_table(conn, 'PA0008', ['PERNR', 'ANSAL', 'WAERS'], max_rows=50)
    print(f"\n  PA0002 after: {len(pa0002_after)} records")
    print(f"  PA0008 after: {len(pa0008_after)} records")


# ============================================================================
# Scenario 2: Vendors (LFA1 / LFBK)
# ============================================================================

def add_vendors(conn):
    print("\n" + "=" * 70)
    print("SCENARIO 2: Vendor Data (LFA1 / LFBK)")
    print("=" * 70)

    lfa1 = read_table(conn, 'LFA1', ['LIFNR', 'NAME1', 'ORT01', 'LAND1'], max_rows=50)
    print(f"  Current LFA1 records: {len(lfa1)}")
    existing_vendors = {r['LIFNR'].lstrip('0') for r in lfa1}

    new_vendors = [
        ('0000002001', 'Krauss-Maffei Industrietechnik', 'Muenchen', 'DE', 'DEUTDEDB', '70020270', '0000123456'),
        ('0000002002', 'Van den Berg Logistics BV', 'Rotterdam', 'NL', 'ABNANL2A', '50000000', '0417164300'),
        ('0000002003', 'Yorkshire Steel Works Ltd', 'Sheffield', 'GB', 'BARCGB22', '204070', '31926819'),
        ('0000002004', 'Fleischer Metallbau GmbH', 'Stuttgart', 'DE', 'SOLADEST', '60050101', '0532013000'),
        ('0000002005', 'De Bruin Chemie NV', 'Antwerpen', 'BE', 'GEBABEBB', '00000000', '539007547034'),
        ('0000002006', 'Nordic Timber Supply AB', 'Goeteborg', 'SE', 'SWEDSESS', '80000000', '058398257466'),
        ('0000002007', 'Precision Tools Italia SRL', 'Milano', 'IT', 'BCITITMM', '03069', '000000123456'),
        ('0000002008', 'Atlantic Freight Services', 'Dublin', 'IE', 'AABORDIE', '93', '5212345678'),
        ('0000002009', 'Elektro Schneider AG', 'Zuerich', 'CH', 'UBSWCHZH', '00230', '623852957'),
        ('0000002010', 'Iberica Packaging SA', 'Barcelona', 'ES', 'CAIXESBB', '2100', '0200051332'),
        ('0000002011', 'Dansk Elektronik ApS', 'Koebenhavn', 'DK', 'DABADKKK', '0040', '0440116243'),
        ('0000002012', 'Wiener Maschinenwerk GmbH', 'Wien', 'AT', 'BKAUATWW', '12000', '0234573201'),
        ('0000002013', 'Polskie Opakowania Sp.z.o.o.', 'Warszawa', 'PL', 'BPKOPLPW', '10201', '071219812874'),
        ('0000002014', 'Loire Valley Wines SARL', 'Tours', 'FR', 'BNPAFRPP', '30004', '567890189'),
        ('0000002015', 'Hellenic Olive Trading SA', 'Athinai', 'GR', 'ETHNGRAA', '011', '012300695'),
    ]

    to_add = [(v, n, c, l, bk, bl, bn) for v, n, c, l, bk, bl, bn in new_vendors
              if v.lstrip('0') not in existing_vendors]
    print(f"  Vendors to add: {len(to_add)}")

    if not to_add:
        print("  All vendors already exist. Skipping.")
        return

    # Go straight to hdbsql INSERT (BAPI_VENDOR_CREATE has complex interface
    # and existing vendor data was created via direct HANA inserts)
    print("\n  Using hdbsql for direct INSERT into LFA1 and LFBK...")
    lfa1_stmts = []
    lfbk_stmts = []
    for v, name, city, country, bkey, bankl, bankn in to_add:
        safe_name = name.replace("'", "''")
        lfa1_stmts.append(
            f"INSERT INTO LFA1 "
            f"(MANDT, LIFNR, LAND1, NAME1, ORT01, SPRAS) "
            f"VALUES ('001', '{v}', '{country}', '{safe_name}', '{city}', 'E')"
        )
        lfbk_stmts.append(
            f"INSERT INTO LFBK "
            f"(MANDT, LIFNR, BANKS, BANKL, BANKN, BVTYP, BKREF) "
            f"VALUES ('001', '{v}', '{country}', '{bankl}', '{bankn}', '', '')"
        )

    print(f"  Inserting {len(lfa1_stmts)} LFA1 records...")
    hdbsql_multi(conn, lfa1_stmts, "LFA1 INSERT")

    print(f"  Inserting {len(lfbk_stmts)} LFBK records...")
    hdbsql_multi(conn, lfbk_stmts, "LFBK INSERT")

    # Verify
    lfa1_after = read_table(conn, 'LFA1', ['LIFNR', 'NAME1'], max_rows=50)
    lfbk_after = read_table(conn, 'LFBK', ['LIFNR', 'BANKS', 'BANKL', 'BANKN'], max_rows=50)
    print(f"\n  LFA1 after: {len(lfa1_after)} vendors")
    print(f"  LFBK after: {len(lfbk_after)} bank details")


# ============================================================================
# Scenario 3: Purchase Orders (EKKO / EKPO)
# ============================================================================

def add_purchase_orders(conn):
    print("\n" + "=" * 70)
    print("SCENARIO 3: Purchase Orders (EKKO / EKPO)")
    print("=" * 70)

    ekko = read_table(conn, 'EKKO', ['EBELN', 'LIFNR', 'BEDAT'], max_rows=50)
    print(f"  Current EKKO records: {len(ekko)}")
    existing_pos = {r['EBELN'] for r in ekko}

    # Get existing vendors for linking
    lfa1 = read_table(conn, 'LFA1', ['LIFNR'], max_rows=50)
    vendor_list = [r['LIFNR'] for r in lfa1]
    if not vendor_list:
        vendor_list = ['0000002001']

    # 15 new purchase orders
    new_pos = [
        ('4500000101', 0, '20260301', 'Server rack assembly', 50, 1250.00),
        ('4500000102', 1, '20260305', 'Hydraulic press components', 200, 345.00),
        ('4500000103', 2, '20260308', 'Steel plate 2mm galvanized', 1000, 28.50),
        ('4500000104', 3, '20260310', 'CNC mill replacement parts', 25, 4200.00),
        ('4500000105', 4, '20260312', 'Chemical cleaning solvent 20L', 100, 89.95),
        ('4500000106', 5, '20260315', 'Timber planks 3m oak', 500, 42.00),
        ('4500000107', 6, '20260318', 'Precision ball bearings', 2000, 12.75),
        ('4500000108', 7, '20260320', 'Maritime shipping container', 5, 8500.00),
        ('4500000109', 8, '20260322', 'Circuit board assembly kit', 300, 156.00),
        ('4500000110', 9, '20260325', 'Industrial packaging rolls', 800, 34.50),
        ('4500000111', 10, '20260328', 'Electronic sensor modules', 150, 275.00),
        ('4500000112', 11, '20260401', 'Stainless steel fittings', 3000, 8.95),
        ('4500000113', 12, '20260403', 'Warehouse shelving units', 40, 620.00),
        ('4500000114', 13, '20260405', 'Wine barrel French oak 225L', 20, 950.00),
        ('4500000115', 14, '20260408', 'Olive oil bulk 1000L', 10, 3200.00),
    ]

    to_add = [(po, vi, dt, desc, qty, pr) for po, vi, dt, desc, qty, pr in new_pos
              if po not in existing_pos]
    print(f"  POs to add: {len(to_add)}")

    if not to_add:
        print("  All POs already exist. Skipping.")
        return

    # Get materials for PO items
    mara = read_table(conn, 'MARA', ['MATNR'], max_rows=50)
    mat_list = [r['MATNR'] for r in mara]
    if not mat_list:
        mat_list = ['Z_SAPMAP_M0001']

    # Try BAPI_PO_CREATE1
    bapi_ok = False
    po_num, vi, bedat, desc, qty, price = to_add[0]
    vendor = vendor_list[vi % len(vendor_list)]
    mat_for_po = mat_list[0]
    print(f"\n  Testing BAPI_PO_CREATE1 for PO with vendor {vendor}, material {mat_for_po}...")
    try:
        r = conn.call('BAPI_PO_CREATE1',
            POHEADER={
                'DOC_TYPE': 'NB',
                'VENDOR': vendor,
                'PURCH_ORG': VKORG,
                'PUR_GROUP': '001',
                'COMP_CODE': BUKRS,
                'DOC_DATE': bedat,
            },
            POHEADERX={
                'DOC_TYPE': 'X',
                'VENDOR': 'X',
                'PURCH_ORG': 'X',
                'PUR_GROUP': 'X',
                'COMP_CODE': 'X',
                'DOC_DATE': 'X',
            },
            POITEM=[{
                'PO_ITEM': '00010',
                'SHORT_TEXT': desc,
                'MATERIAL': mat_for_po,
                'PLANT': PLANT,
                'QUANTITY': str(qty),
                'NET_PRICE': str(price),
                'PRICE_UNIT': '1',
                'TAX_CODE': 'V0',
                'ACCTASSCAT': 'K',
                'ITEM_CAT': '',
            }],
            POITEMX=[{
                'PO_ITEM': '00010',
                'PO_ITEMX': 'X',
                'SHORT_TEXT': 'X',
                'MATERIAL': 'X',
                'PLANT': 'X',
                'QUANTITY': 'X',
                'NET_PRICE': 'X',
                'PRICE_UNIT': 'X',
                'TAX_CODE': 'X',
                'ACCTASSCAT': 'X',
            }],
        )
        po_out = (r.get('PURCHASEORDER', '') or r.get('PO_NUMBER', '') or '').strip()
        ret = r.get('RETURN', [])
        if po_out and po_out != '0000000000':
            print(f"    [OK] PO created: {po_out}")
            commit(conn)
            bapi_ok = True
            to_add = to_add[1:]
        else:
            print_ret(ret if isinstance(ret, list) else [ret])
            rollback(conn)
    except Exception as e:
        print(f"    BAPI error: {e}")
        rollback(conn)

    if bapi_ok:
        for po_num, vi, bedat, desc, qty, price in to_add:
            vendor = vendor_list[vi % len(vendor_list)]
            mat_item = mat_list[vi % len(mat_list)]
            print(f"  Creating PO: {desc[:40]}... vendor={vendor}")
            try:
                r = conn.call('BAPI_PO_CREATE1',
                    POHEADER={
                        'DOC_TYPE': 'NB',
                        'VENDOR': vendor,
                        'PURCH_ORG': VKORG,
                        'PUR_GROUP': '001',
                        'COMP_CODE': BUKRS,
                        'DOC_DATE': bedat,
                    },
                    POHEADERX={
                        'DOC_TYPE': 'X',
                        'VENDOR': 'X',
                        'PURCH_ORG': 'X',
                        'PUR_GROUP': 'X',
                        'COMP_CODE': 'X',
                        'DOC_DATE': 'X',
                    },
                    POITEM=[{
                        'PO_ITEM': '00010',
                        'SHORT_TEXT': desc,
                        'MATERIAL': mat_item,
                        'PLANT': PLANT,
                        'QUANTITY': str(qty),
                        'NET_PRICE': str(price),
                        'PRICE_UNIT': '1',
                        'TAX_CODE': 'V0',
                        'ACCTASSCAT': 'K',
                    }],
                    POITEMX=[{
                        'PO_ITEM': '00010',
                        'PO_ITEMX': 'X',
                        'SHORT_TEXT': 'X',
                        'MATERIAL': 'X',
                        'PLANT': 'X',
                        'QUANTITY': 'X',
                        'NET_PRICE': 'X',
                        'PRICE_UNIT': 'X',
                        'TAX_CODE': 'X',
                        'ACCTASSCAT': 'X',
                    }],
                )
                po_out = (r.get('PURCHASEORDER', '') or r.get('PO_NUMBER', '') or '').strip()
                ret = r.get('RETURN', [])
                if po_out and po_out != '0000000000':
                    print(f"    [OK] {po_out}")
                    commit(conn)
                else:
                    print_ret(ret if isinstance(ret, list) else [ret])
                    rollback(conn)
            except Exception as e:
                print(f"    Error: {e}")
                rollback(conn)
    else:
        # Fall back to hdbsql
        print("\n  BAPI failed. Using hdbsql for EKKO/EKPO INSERT...")
        ekko_stmts = []
        ekpo_stmts = []
        for po_num, vi, bedat, desc, qty, price in to_add:
            vendor = vendor_list[vi % len(vendor_list)]
            safe_desc = desc.replace("'", "''")
            ekko_stmts.append(
                f"INSERT INTO EKKO "
                f"(MANDT, EBELN, BUKRS, BSTYP, BSART, LIFNR, EKORG, EKGRP, "
                f"WAERS, BEDAT, ERNAM) "
                f"VALUES ('001', '{po_num}', '{BUKRS}', 'F', 'NB', '{vendor}', "
                f"'{VKORG}', '001', 'EUR', '{bedat}', 'SAPMAP')"
            )
            netval = qty * price
            ekpo_stmts.append(
                f"INSERT INTO EKPO "
                f"(MANDT, EBELN, EBELP, TXZ01, MENGE, MEINS, NETPR, PEINH, "
                f"WERKS) "
                f"VALUES ('001', '{po_num}', '00010', '{safe_desc}', "
                f"{qty:.3f}, 'ST', {price:.2f}, 1, '{PLANT}')"
            )

        print(f"  Inserting {len(ekko_stmts)} EKKO records...")
        hdbsql_multi(conn, ekko_stmts, "EKKO INSERT")

        print(f"  Inserting {len(ekpo_stmts)} EKPO records...")
        hdbsql_multi(conn, ekpo_stmts, "EKPO INSERT")

    # Verify
    ekko_after = read_table(conn, 'EKKO', ['EBELN', 'LIFNR', 'BEDAT'], max_rows=50)
    ekpo_after = read_table(conn, 'EKPO', ['EBELN', 'EBELP', 'TXZ01', 'NETPR'], max_rows=50)
    print(f"\n  EKKO after: {len(ekko_after)} purchase orders")
    print(f"  EKPO after: {len(ekpo_after)} line items")


# ============================================================================
# Scenario 5: Customers (KNA1)
# ============================================================================

def add_customers(conn):
    print("\n" + "=" * 70)
    print("SCENARIO 5: Customer Data (KNA1)")
    print("=" * 70)

    kna1 = read_table(conn, 'KNA1', ['KUNNR', 'NAME1', 'ORT01', 'LAND1'], max_rows=50)
    print(f"  Current KNA1 records: {len(kna1)}")
    existing_custs = {r['KUNNR'].lstrip('0') for r in kna1}

    new_customers = [
        ('Norddeutsche Baumaschinen GmbH', 'Hannover', '30159', 'DE', 'Marktstrasse 45'),
        ('British Aerospace Components Ltd', 'Bristol', 'BS1 4DJ', 'GB', '12 Queens Road'),
        ('Hollandse Zuivel Cooeperatie', 'Gouda', '2801 AA', 'NL', 'Kaasmarkt 8'),
        ('Osterreichische Stahlwerke AG', 'Linz', '4020', 'AT', 'Industriezeile 28'),
        ('Scandinavian Furniture Design AB', 'Malmoe', '21135', 'SE', 'Storgatan 15'),
        ('Mediterran Textil SA', 'Barcelona', '08002', 'ES', 'Passeig de Gracia 55'),
        ('Celtic Engineering Works', 'Glasgow', 'G1 2FF', 'GB', '7 Buchanan Street'),
        ('Alpenlaendische Molkerei AG', 'Innsbruck', '6020', 'AT', 'Maria-Theresien-Str 18'),
        ('Vlaamse Chemie Groep NV', 'Gent', '9000', 'BE', 'Kouter 29'),
        ('Hanseatische Reederei GmbH', 'Hamburg', '20457', 'DE', 'Speicherstadt 11'),
    ]

    # Go straight to hdbsql INSERT (existing customer data is via direct HANA inserts)
    print("\n  Using hdbsql for KNA1 INSERT...")
    stmts = []
    for idx, (name, city, pstlz, country, street) in enumerate(new_customers):
        kunnr = f'{3001 + idx:010d}'
        safe_name = name.replace("'", "''")
        safe_street = street.replace("'", "''")
        stmts.append(
            f"INSERT INTO KNA1 "
            f"(MANDT, KUNNR, NAME1, STRAS, ORT01, PSTLZ, LAND1, SPRAS, KTOKD) "
            f"VALUES ('001', '{kunnr}', '{safe_name}', '{safe_street}', "
            f"'{city}', '{pstlz}', '{country}', 'E', '0001')"
        )
    hdbsql_multi(conn, stmts, "KNA1 INSERT")

    # Verify
    kna1_after = read_table(conn, 'KNA1', ['KUNNR', 'NAME1', 'ORT01', 'LAND1'], max_rows=50)
    print(f"\n  KNA1 after: {len(kna1_after)} customers")
    for r in kna1_after[-10:]:
        print(f"    {r['KUNNR']} | {r['NAME1']} | {r['ORT01']} | {r['LAND1']}")


# ============================================================================
# Scenario 6: Materials (MARA / MAKT)
# ============================================================================

def add_materials(conn):
    print("\n" + "=" * 70)
    print("SCENARIO 6: Material Data (MARA / MAKT)")
    print("=" * 70)

    mara = read_table(conn, 'MARA', ['MATNR', 'MTART'], max_rows=60)
    print(f"  Current MARA records: {len(mara)}")
    existing_mats = {r['MATNR'].strip() for r in mara}

    new_materials = [
        ('Z_SAPMAP_M0026', 'Industrial Servo Motor 5kW'),
        ('Z_SAPMAP_M0027', 'Stainless Steel Valve DN50'),
        ('Z_SAPMAP_M0028', 'Carbon Fiber Composite Sheet'),
        ('Z_SAPMAP_M0029', 'LED Panel Light 60x60'),
        ('Z_SAPMAP_M0030', 'Aluminum Extrusion Profile'),
        ('Z_SAPMAP_M0031', 'Hydraulic Cylinder 100mm'),
        ('Z_SAPMAP_M0032', 'Polyethylene Granulate HD'),
        ('Z_SAPMAP_M0033', 'Copper Wire Cable 16mm2'),
        ('Z_SAPMAP_M0034', 'Ceramic Insulator High-Volt'),
        ('Z_SAPMAP_M0035', 'Titanium Alloy Rod Ti-6Al-4V'),
        ('Z_SAPMAP_M0036', 'Rubber Gasket Set Universal'),
        ('Z_SAPMAP_M0037', 'Optical Fiber Cable SM 12F'),
        ('Z_SAPMAP_M0038', 'Epoxy Resin 2-Component'),
        ('Z_SAPMAP_M0039', 'Pneumatic Actuator DA 80'),
        ('Z_SAPMAP_M0040', 'Silicon Wafer 300mm Grade A'),
    ]

    to_add = [(m, d) for m, d in new_materials if m not in existing_mats]
    print(f"  Materials to add: {len(to_add)}")

    if not to_add:
        print("  All materials already exist. Skipping.")
        return

    # Try BAPI_MATERIAL_SAVEDATA
    bapi_ok = False
    mat, desc = to_add[0]
    print(f"\n  Testing BAPI_MATERIAL_SAVEDATA for {mat}...")
    try:
        r = conn.call('BAPI_MATERIAL_SAVEDATA',
            HEADDATA={
                'MATERIAL': mat,
                'IND_SECTOR': 'M',
                'MATL_TYPE': 'HAWA',
                'BASIC_VIEW': 'X',
            },
            CLIENTDATA={
                'BASE_UOM': 'ST',
            },
            CLIENTDATAX={
                'BASE_UOM': 'X',
            },
            MATERIALDESCRIPTION=[{
                'LANGU': 'E',
                'MATL_DESC': desc,
            }],
        )
        ret = r.get('RETURN', {})
        if has_err(ret):
            print_ret(ret if isinstance(ret, list) else [ret])
            rollback(conn)
        else:
            commit(conn)
            bapi_ok = True
            to_add = to_add[1:]
            print(f"    [OK] Material created: {mat}")
    except Exception as e:
        print(f"    BAPI error: {e}")
        rollback(conn)

    if bapi_ok:
        for mat, desc in to_add:
            print(f"  Creating material {mat}: {desc}")
            try:
                r = conn.call('BAPI_MATERIAL_SAVEDATA',
                    HEADDATA={
                        'MATERIAL': mat,
                        'IND_SECTOR': 'M',
                        'MATL_TYPE': 'HAWA',
                        'BASIC_VIEW': 'X',
                    },
                    CLIENTDATA={
                        'BASE_UOM': 'ST',
                    },
                    CLIENTDATAX={
                        'BASE_UOM': 'X',
                    },
                    MATERIALDESCRIPTION=[{
                        'LANGU': 'E',
                        'MATL_DESC': desc,
                    }],
                )
                ret = r.get('RETURN', {})
                if has_err(ret):
                    print_ret(ret if isinstance(ret, list) else [ret])
                    rollback(conn)
                else:
                    commit(conn)
                    print(f"    [OK]")
            except Exception as e:
                print(f"    Error: {e}")
                rollback(conn)

        # Also extend with sales views (skip MRP_VIEW as it requires MRP_TYPE)
        print("\n  Extending new materials with sales views...")
        all_new_mats = [m for m, _ in new_materials if m not in existing_mats]
        for mat in all_new_mats:
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
                    TAXCLASSIFICATIONS=[{
                        'DEPCOUNTRY': 'DE',
                        'TAX_TYPE_1': 'MWST',
                        'TAXCLASS_1': '1',
                    }],
                )
                ret = r.get('RETURN', {})
                if has_err(ret):
                    rollback(conn)
                else:
                    commit(conn)
                    print(f"    [OK] {mat} extended with sales view")
            except Exception as e:
                print(f"    [WARN] {mat} extension: {e}")
                rollback(conn)
    else:
        # Fall back to hdbsql
        print("\n  BAPI failed. Using hdbsql for MARA/MAKT INSERT...")
        mara_stmts = []
        makt_stmts = []
        for mat, desc in to_add:
            safe_desc = desc.replace("'", "''")
            mara_stmts.append(
                f"INSERT INTO MARA "
                f"(MANDT, MATNR, MTART, MBRSH, MEINS) "
                f"VALUES ('001', '{mat}', 'HAWA', 'M', 'ST')"
            )
            makt_stmts.append(
                f"INSERT INTO MAKT "
                f"(MANDT, MATNR, SPRAS, MAKTX) "
                f"VALUES ('001', '{mat}', 'E', '{safe_desc}')"
            )
        hdbsql_multi(conn, mara_stmts, "MARA INSERT")
        hdbsql_multi(conn, makt_stmts, "MAKT INSERT")

    # Verify
    mara_after = read_table(conn, 'MARA', ['MATNR', 'MTART'], max_rows=60)
    makt_after = read_table(conn, 'MAKT', ['MATNR', 'MAKTX'], max_rows=60,
                            where="MATNR LIKE 'Z_SAPMAP%'")
    print(f"\n  MARA after: {len(mara_after)} materials")
    print(f"  MAKT (Z_SAPMAP*): {len(makt_after)} descriptions")


# ============================================================================
# Scenario 7: Sales Orders (VBAK)
# ============================================================================

def add_sales_orders(conn):
    print("\n" + "=" * 70)
    print("SCENARIO 7: Sales Orders (VBAK)")
    print("  Note: Existing orders are direct HANA inserts (KNVV empty).")
    print("  Using hdbsql INSERT to match existing approach.")
    print("=" * 70)

    vbak = read_table(conn, 'VBAK', ['VBELN', 'AUART', 'KUNNR', 'NETWR', 'WAERK'], max_rows=50)
    print(f"  Current VBAK records: {len(vbak)}")
    existing_vbeln = {r['VBELN'] for r in vbak}
    total_existing = sum(float(r['NETWR'].replace(',', '')) for r in vbak if r.get('NETWR'))
    print(f"  Current total value: EUR {total_existing:,.2f}")

    # Get customer list
    kna1 = read_table(conn, 'KNA1', ['KUNNR'], max_rows=30)
    cust_list = [r['KUNNR'] for r in kna1]
    if not cust_list:
        cust_list = [f'{i:010d}' for i in range(1, 11)]

    # 10 new sales orders — target EUR 2-3M additional
    order_specs = [
        ('0000000211', 1, 'OR', 180000.00, 'Rush order - electronics'),
        ('0000000212', 2, 'OR', 255000.00, 'Framework agreement delivery'),
        ('0000000213', 3, 'OR', 320000.00, 'Bulk material delivery'),
        ('0000000214', 4, 'OR', 145000.00, 'Premium components'),
        ('0000000215', 5, 'OR', 275000.00, 'Quarterly supply run'),
        ('0000000216', 6, 'OR', 190000.00, 'Production line supplies'),
        ('0000000217', 7, 'OR', 410000.00, 'High volume standard parts'),
        ('0000000218', 8, 'OR', 95000.00, 'Specialized equipment'),
        ('0000000219', 9, 'OR', 168000.00, 'Seasonal stock-up'),
        ('0000000220', 10, 'OR', 362000.00, 'Project order - automotive'),
    ]

    to_add = [(v, ci, t, n, d) for v, ci, t, n, d in order_specs
              if v not in existing_vbeln]
    print(f"  Orders to add: {len(to_add)}")

    if not to_add:
        print("  All sales orders already exist. Skipping.")
        return

    stmts = []
    for vbeln, ci, auart, netwr, desc in to_add:
        cust = cust_list[ci % len(cust_list)]
        stmts.append(
            f"INSERT INTO VBAK "
            f"(MANDT, VBELN, ERDAT, ERZET, ERNAM, AUART, NETWR, WAERK, KUNNR) "
            f"VALUES ('001', '{vbeln}', '20260410', '120000', 'SAPMAP', "
            f"'{auart}', {netwr:.2f}, 'EUR', '{cust}')"
        )

    print(f"\n  Inserting {len(stmts)} VBAK records via hdbsql...")
    hdbsql_multi(conn, stmts, "VBAK INSERT")

    # Verify
    vbak_after = read_table(conn, 'VBAK', ['VBELN', 'NETWR', 'WAERK'], max_rows=50)
    total_after = sum(float(r['NETWR'].replace(',', '')) for r in vbak_after if r.get('NETWR'))
    print(f"\n  VBAK after: {len(vbak_after)} orders, total: EUR {total_after:,.2f}")


# ============================================================================
# Scenario 8: Production / Planned Orders (AUFK / PLAF)
# ============================================================================

def add_production_orders(conn):
    print("\n" + "=" * 70)
    print("SCENARIO 8: Production & Planned Orders (AUFK / PLAF)")
    print("=" * 70)

    aufk = read_table(conn, 'AUFK', ['AUFNR', 'AUART'], max_rows=30)
    plaf = read_table(conn, 'PLAF', ['PLNUM', 'MATNR', 'GSMNG'], max_rows=30)
    print(f"  Current AUFK orders: {len(aufk)}")
    print(f"  Current PLAF planned orders: {len(plaf)}")

    # Get materials with in-house procurement
    marc = read_table(conn, 'MARC', ['MATNR', 'WERKS', 'BESKZ'], max_rows=50)
    in_house_mats = [r['MATNR'] for r in marc if r.get('BESKZ') == 'E']
    all_mats = [r['MATNR'] for r in marc]
    prod_mats = in_house_mats if in_house_mats else all_mats[:10]
    print(f"  Available materials for production: {len(prod_mats)}")

    # 10 new planned orders
    planned_specs = [
        (0, 200, '20260501', '20260515', 'Additional batch 1'),
        (1, 500, '20260505', '20260520', 'Ramp-up production'),
        (2, 800, '20260510', '20260525', 'Customer demand surge'),
        (3, 150, '20260515', '20260530', 'Safety stock replenish'),
        (4, 1200, '20260520', '20260605', 'Q3 pre-production'),
        (0, 350, '20260525', '20260610', 'Expedited order'),
        (1, 600, '20260601', '20260615', 'Continuous flow batch'),
        (2, 900, '20260605', '20260620', 'Peak season build'),
        (3, 250, '20260610', '20260625', 'Maintenance stock'),
        (4, 1500, '20260615', '20260630', 'Annual contract volume'),
    ]

    created_planned = []
    print(f"\n  Creating {len(planned_specs)} planned orders via BAPI...")

    for idx, (mi, qty, start, end, desc) in enumerate(planned_specs):
        mat = prod_mats[mi % len(prod_mats)]
        print(f"  [{idx+1}] Mat={mat}, Qty={qty}, {start}-{end} ({desc})")

        try:
            r = conn.call('BAPI_PLANNEDORDER_CREATE',
                HEADERDATA={
                    'MATERIAL': mat,
                    'PLAN_PLANT': PLANT,
                    'PROD_PLANT': PLANT,
                    'TOTAL_PLORD_QTY': str(qty),
                    'PLAN_OPEN_DATE': start,
                    'ORDER_FIN_DATE': end,
                    'PLDORD_PROFILE': 'NB',
                },
            )
            po_num = (r.get('PLANNEDORDER', '') or '').strip()
            ret = r.get('RETURN', {})
            if po_num:
                print(f"    [OK] Planned order: {po_num}")
                commit(conn)
                created_planned.append(po_num)
            else:
                if isinstance(ret, dict):
                    print(f"    [{ret.get('TYPE','')}] {ret.get('MESSAGE','')}")
                else:
                    print_ret(ret)
                rollback(conn)
        except Exception as e:
            print(f"    Error: {e}")
            rollback(conn)

    if not created_planned:
        # Fall back to hdbsql for PLAF
        print("\n  BAPI failed. Using hdbsql for PLAF INSERT...")
        stmts = []
        for idx, (mi, qty, start, end, desc) in enumerate(planned_specs):
            mat = prod_mats[mi % len(prod_mats)]
            plnum = f'{900000 + idx:010d}'
            stmts.append(
                f"INSERT INTO PLAF "
                f"(MANDT, PLNUM, MATNR, PLWRK, GSMNG, PSTTR, PEDTR, PLART) "
                f"VALUES ('001', '{plnum}', '{mat}', '{PLANT}', "
                f"{qty:.3f}, '{start}', '{end}', 'NB')"
            )
        hdbsql_multi(conn, stmts, "PLAF INSERT")

    # Verify
    plaf_after = read_table(conn, 'PLAF', ['PLNUM', 'MATNR', 'GSMNG'], max_rows=50)
    aufk_after = read_table(conn, 'AUFK', ['AUFNR', 'AUART'], max_rows=50)
    print(f"\n  PLAF after: {len(plaf_after)} planned orders")
    print(f"  AUFK after: {len(aufk_after)} production orders")


# ============================================================================
# Final Verification
# ============================================================================

def final_verification(conn):
    print("\n" + "=" * 70)
    print("FINAL VERIFICATION - ALL TABLES")
    print("=" * 70)

    checks = [
        ('PA0002', ['PERNR', 'VORNA', 'NACHN'], 'HR Employees'),
        ('PA0008', ['PERNR', 'ANSAL', 'WAERS'], 'HR Salaries'),
        ('LFA1',  ['LIFNR', 'NAME1'], 'Vendors'),
        ('LFBK',  ['LIFNR', 'BANKS', 'BANKN'], 'Vendor Bank Details'),
        ('EKKO',  ['EBELN', 'LIFNR', 'BEDAT'], 'Purchase Orders'),
        ('EKPO',  ['EBELN', 'EBELP', 'TXZ01'], 'PO Line Items'),
        ('USR02', ['BNAME'], 'User Accounts (unchanged)'),
        ('AGR_USERS', ['UNAME', 'AGR_NAME'], 'Role Assignments (unchanged)'),
        ('KNA1',  ['KUNNR', 'NAME1'], 'Customers'),
        ('MARA',  ['MATNR', 'MTART'], 'Materials'),
        ('MAKT',  ['MATNR', 'MAKTX'], 'Material Descriptions'),
        ('MVKE',  ['MATNR', 'VKORG'], 'Material Sales Views'),
        ('VBAK',  ['VBELN', 'AUART', 'NETWR', 'WAERK'], 'Sales Orders'),
        ('AUFK',  ['AUFNR', 'AUART'], 'Production Orders'),
        ('PLAF',  ['PLNUM', 'MATNR', 'GSMNG'], 'Planned Orders'),
    ]

    print(f"\n  {'Table':<12} {'Description':<30} {'Count':>6}")
    print("  " + "-" * 52)

    results = {}
    for table, fields, desc in checks:
        rows = read_table(conn, table, fields, max_rows=200)
        count = len(rows)
        results[table] = count
        print(f"  {table:<12} {desc:<30} {count:>6}")

    # VBAK total value
    vbak = read_table(conn, 'VBAK', ['VBELN', 'NETWR'], max_rows=50)
    total_val = sum(float(r['NETWR'].replace(',', '')) for r in vbak if r.get('NETWR'))
    print(f"\n  Total Sales Order Value: EUR {total_val:,.2f}")

    # PA0008 salary range
    pa0008 = read_table(conn, 'PA0008', ['PERNR', 'ANSAL'], max_rows=50)
    if pa0008:
        salaries = []
        for r in pa0008:
            try:
                salaries.append(float(r['ANSAL'].replace(',', '')))
            except:
                pass
        if salaries:
            print(f"  Salary range: EUR {min(salaries):,.2f} - EUR {max(salaries):,.2f}")
            print(f"  Average salary: EUR {sum(salaries)/len(salaries):,.2f}")

    # PLAF total planned quantity
    plaf = read_table(conn, 'PLAF', ['PLNUM', 'GSMNG'], max_rows=50)
    total_qty = sum(float(r['GSMNG'].replace(',', '')) for r in plaf if r.get('GSMNG'))
    print(f"  Total Planned Production Qty: {total_qty:,.0f} units")

    # EKKO total PO value
    ekpo = read_table(conn, 'EKPO', ['EBELN', 'NETPR', 'MENGE'], max_rows=100)
    total_po = 0
    for r in ekpo:
        try:
            total_po += float(r.get('NETPR', '0').replace(',', '')) * float(r.get('MENGE', '0').replace(',', ''))
        except:
            pass
    print(f"  Total PO Value (approx): EUR {total_po:,.2f}")

    print("\n  " + "=" * 52)
    print("  Data doubling complete.")


# ============================================================================
# Main
# ============================================================================

def main():
    print("=" * 70)
    print("DOUBLE DEMO DATA - S4H Business Impact Scenarios")
    print("=" * 70)
    print(f"Host: {CONN_PARAMS['ashost']}, Instance: {CONN_PARAMS['sysnr']}, "
          f"Client: {CONN_PARAMS['client']}")
    print()

    with RFCConnection(**CONN_PARAMS) as conn:
        print("[+] RFC connection established\n")

        # Scenario 1: HR Data
        add_hr_data(conn)

        # Scenario 2: Vendors
        add_vendors(conn)

        # Scenario 3: Purchase Orders
        add_purchase_orders(conn)

        # Scenario 4: USR02/AGR_USERS — SKIP (already 46 users)
        print("\n" + "=" * 70)
        print("SCENARIO 4: User Accounts (USR02/AGR_USERS) — SKIPPED")
        print("  Already have 46 users, which is plenty for the demo.")
        print("=" * 70)

        # Scenario 5: Customers
        add_customers(conn)

        # Scenario 6: Materials
        add_materials(conn)

        # Scenario 7: Sales Orders
        add_sales_orders(conn)

        # Scenario 8: Production/Planned Orders
        add_production_orders(conn)

        # Final verification
        final_verification(conn)


if __name__ == '__main__':
    main()
