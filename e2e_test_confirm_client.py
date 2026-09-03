import os, sys, io, re, hmac
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

os.environ.setdefault('SECRET_KEY', 'e2e-test-dummy-secret-9876543210-12345-abcdef')
os.environ.setdefault('FLASK_DEBUG', '1')
os.environ['DEBUG_POST_COMMIT_500'] = ''

import json as _json
from app import create_app

app = create_app()
app.testing = True
app.config['TESTING'] = True
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_CHECK_DEFAULT'] = True

DELIVERY_ID = 140
ORDER_ID = 47
TOKEN = 'YCUYQUGY7TO6'

REAL_USER_ID = None
REAL_TECH_ID = None

with app.app_context():
    try:
        from app.models import get_db, is_postgres
        db_inst = get_db()
        phx = '%s' if is_postgres() else '?'
        cur = db_inst.execute(
            f'UPDATE technician_badge_deliveries SET client_confirmed_at=NULL, client_name=NULL, client_company=NULL, client_phone=NULL, client_ip_hash=NULL, client_user_agent=NULL WHERE id = {phx}',
            (DELIVERY_ID,)
        )
        cur2 = db_inst.execute(
            f'UPDATE technician_orders SET client_name=NULL, client_address=NULL, client_phone=NULL, badge_delivery_id={phx} WHERE id = {phx}',
            (DELIVERY_ID, ORDER_ID)
        )
        db_inst.commit()
        print('[PREP] clean delivery=%d rows=%d | order=%d rows=%d OK' % (DELIVERY_ID, cur.rowcount or 0, ORDER_ID, cur2.rowcount or 0))

        row_o = db_inst.execute(f'SELECT technician_id, badge_delivery_id FROM technician_orders WHERE id = {phx}', (ORDER_ID,)).fetchone()
        if row_o:
            REAL_TECH_ID = row_o["technician_id"]
            print('[PREP] OT %d technician_id = %s | bdid = %s' % (ORDER_ID, REAL_TECH_ID, row_o["badge_delivery_id"]))

        if REAL_TECH_ID:
            row_u = db_inst.execute(f'SELECT id, username, role, is_active FROM users WHERE technician_id = {phx} LIMIT 1', (REAL_TECH_ID,)).fetchone()
            if row_u:
                REAL_USER_ID = row_u["id"]
                print('[PREP] users.technician_id=%s -> user_id=%d user=%s role=%s active=%s' % (REAL_TECH_ID, REAL_USER_ID, row_u["username"], row_u["role"], row_u["is_active"]))
            else:
                row_a = db_inst.execute(f'SELECT id, username, role, is_active FROM users WHERE is_active=1 AND (role=\'technician\' OR role=\'admin\') ORDER BY id ASC LIMIT 1').fetchone()
                if row_a:
                    REAL_USER_ID = row_a["id"]
                    REAL_TECH_ID = None
                    print('[PREP] NO user->tech link; fallback ANY active user id=%d user=%s role=%s' % (REAL_USER_ID, row_a["username"], row_a["role"]))
    except Exception as e:
        import traceback; traceback.print_exc()
        print('[PREP] error:', repr(e)[:500])

if not REAL_USER_ID:
    REAL_USER_ID = 79
    print('[PREP] WARNING usando user_id hardcodeado 79 (ninguno encontrado)')

print('\n=== CONFIG E2E ===')
print(' DELIVERY_ID =', DELIVERY_ID)
print(' ORDER_ID    =', ORDER_ID)
print(' TOKEN       =', TOKEN)
print(' REAL_USER_ID=', REAL_USER_ID)
print(' REAL_TECH_ID=', REAL_TECH_ID)
print('==================\n')

CSRF_RE = re.compile(r'<input\s+[^>]*name=["\']csrf_token["\'][^>]*value=["\']([^"\']+)["\']', re.IGNORECASE | re.DOTALL)

with app.test_client() as c:
    with app.app_context():
        with c.session_transaction() as sess:
            sess.clear()
            sess['user_id'] = REAL_USER_ID
            sess['_fresh'] = True
            print('[SESS] session cargada user_id=%s keys=%s' % (sess.get('user_id'), list(sess.keys())))

    print('--- GET confirm-client?d=%s (extraer csrf) ---' % DELIVERY_ID)
    resp_get = c.get(
        '/t/%s/confirm-client?d=%d' % (TOKEN, DELIVERY_ID),
        follow_redirects=True
    )
    print('[GET] status_code =', resp_get.status_code, 'len(body)=', len(resp_get.data or b''))
    get_txt = (resp_get.data or b'').decode('utf-8', errors='ignore')
    m = CSRF_RE.search(get_txt)
    csrf_val = m.group(1) if m else None
    with app.test_client() as _c2:
        with _c2.session_transaction() as _sess_check:
            pass
    with c.session_transaction() as sess_after_get:
        _csrf_in_session = sess_after_get.get('_csrf_token')
        print('[GET] session["_csrf_token"] existe =', bool(_csrf_in_session), 'len =', len(_csrf_in_session or ''))
    print('[GET] csrf_token extraído de HTML =', csrf_val[:32] + '...' if csrf_val and len(csrf_val) > 32 else csrf_val)
    if not csrf_val:
        print('[GET] WARNING: no se pudo extraer csrf de HTML. Buscando alternativas...')
        m2 = re.search(r'name=csrf_token\s+value=["\']([^"\']+)["\']', get_txt, re.IGNORECASE)
        if m2:
            csrf_val = m2.group(1)
            print('[GET] alternativa re2 funcionó. csrf_token =', csrf_val[:32] + '...')
        else:
            print('[GET] DEBUG: últimos 2000 chars HTML:')
            print(get_txt[-2000:])

    print('\n--- POST confirm-client d=%s csrf_ok esperado=1 ---' % DELIVERY_ID)
    post_data = {
        'client_name': 'Ramón Cabral',
        'client_company': 'San Martín 1234',
        'client_phone': '2615893590',
        'd': str(DELIVERY_ID),
    }
    if csrf_val:
        post_data['csrf_token'] = csrf_val
    resp_post = c.post(
        '/t/%s/confirm-client?d=%d' % (TOKEN, DELIVERY_ID),
        data=post_data,
        follow_redirects=True
    )
    print('[POST] status_code =', resp_post.status_code, 'len(body)=', len(resp_post.data or b''))
    resp_txt = (resp_post.data or b'').decode('utf-8', errors='ignore')
    needle_list = ['ya confirmaste', 'confirmación exitosa', 'gracias por confirmar', 'ramón', 'confirmaste esta credencial', 'listo', 'correctamente']
    has_success = any(n in resp_txt.lower() for n in needle_list)
    has_error = any(x in resp_txt.lower() for x in ['token de seguridad', 'error', 'falló', 'inválido'])
    print('[POST] success-card visible =', has_success)
    print('[POST] error-card visible     =', has_error)

    if has_success and has_error:
        print('\n******************** BUG 11 DETECTADO ********************')
        print(' POST tuvo error PERO success-card sigue visible')
        print('**********************************************************\n')

    print('\n--- GET status.json order=%d ---' % ORDER_ID)
    resp_status = c.get('/orders/%d/status.json' % ORDER_ID, headers={'Accept': 'application/json'})
    print('[STATUS] status_code =', resp_status.status_code)
    j = None
    try:
        j = _json.loads(resp_status.data)
    except Exception as e:
        print('[STATUS] parse error:', repr(e), 'raw:', (resp_status.data or b'')[:500])
    if j:
        print('[STATUS] payload keys =', list(j.keys()))
        print('[STATUS] payload preview =', _json.dumps(j, ensure_ascii=False, indent=2)[:3000])
        if j.get('ok'):
            dlv = j.get('delivery') or {}
            odr = j.get('order') or {}
            print('\n========= RESULTADOS FINALES E2E =========')
            print(' has_sent        =', j.get('has_sent'))
            print(' has_confirm     =', j.get('has_confirm'))
            print(' delivery.id     =', dlv.get('id'))
            print(' delivery.name   =', dlv.get('client_name'))
            print(' delivery.company=', dlv.get('client_company'))
            print(' delivery.confAt =', dlv.get('client_confirmed_at'))
            print(' order.bdid      =', odr.get('badge_delivery_id'))
            print(' order.cname     =', odr.get('client_name'))
            print(' order.caddr     =', odr.get('client_address'))
            print(' order.cphone    =', odr.get('client_phone'))
            EXPECTED_OK = (
                bool(j.get('has_sent'))
                and bool(j.get('has_confirm'))
                and (dlv.get('client_name') or '').strip().lower() == 'ramón cabral'
                and (dlv.get('client_company') or '').strip() == 'San Martín 1234'
                and (odr.get('client_name') or '').strip().lower() == 'ramón cabral'
                and (odr.get('client_address') or '').strip() == 'San Martín 1234'
            )
            print('===========================================')
            print(' TEST_PASS =', EXPECTED_OK)
            print('===========================================')
        else:
            print('[STATUS] ok=false. error =', j.get('error'), 'redirect =', j.get('redirect'))
    else:
        print('[STATUS] NO JSON. body primeros 1500 chars:')
        print((resp_status.data or b'').decode('utf-8', errors='ignore')[:1500])
