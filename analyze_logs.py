import sys, json, collections

if __name__ == '__main__':
    if len(sys.argv)<2:
        print('Usage: python analyze_logs.py logs/server.jsonl'); sys.exit(1)
    p = sys.argv[1]
    events = []
    with open(p,'r',encoding='utf-8') as f:
        for line in f:
            events.append(json.loads(line))
    by_event = collections.Counter(e['event'] for e in events)
    auth_fail = [e for e in events if e['event']=='auth.fail']
    bad_hmac = [e for e in events if e['event']=='data.bad_hmac']
    invalid_token = [e for e in events if e['event']=='data.invalid_token']
    tls_fail = [e for e in events if e['event']=='tls.fail']
    locked = [e for e in events if e['event']=='auth.locked']
    print('Events count:', dict(by_event))
    print('TLS handshake fails:', len(tls_fail))
    for e in tls_fail:
        print('  ', e['ts'], e.get('peer'), e.get('err'))
    print('Auth fails:', len(auth_fail))
    # peer має вигляд "('127.0.0.1', 55150)": групуємо за IP без порту, бо порт щоразу новий
    offenders = collections.Counter((e.get('peer','?').split(',')[0].strip("('"), e.get('user','?')) for e in auth_fail)
    print('Top offenders:', offenders.most_common(5))
    print('Locked accounts:', [(e['ts'], e.get('user')) for e in locked])
    print('Bad HMAC:', len(bad_hmac), 'Invalid token:', len(invalid_token))
    # Нетипові випадки: повторювані помилки автентифікації (>= 3) для одного користувача
    for (ip, user), n in offenders.items():
        if n >= 3:
            print(f'ALERT: {n} failed logins for user "{user}" - possible password guessing')
