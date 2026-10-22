"""Command-line entry point. Run python cli.py --help."""
import argparse
import json
from pathlib import Path
from firewall import policy, save_policy, simulate

ROOT = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description='Sentinel • educational firewall simulator')
    parser.add_argument('--policy', default='data/policy.json')
    parser.add_argument('--log', default='data/traffic.jsonl')
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('init', help='Create starter policy (refuses to overwrite)')
    commands.add_parser('rules', help='List rules in evaluation order')
    default = commands.add_parser('default')
    default.add_argument('action', choices=['ALLOW', 'BLOCK'])
    add = commands.add_parser('add', help='Append rule; earlier rules take precedence')
    add.add_argument('id')
    add.add_argument('action', choices=['ALLOW', 'BLOCK'])
    add.add_argument('--source', default='ANY')
    add.add_argument('--destination', default='ANY')
    add.add_argument('--protocol', default='ANY')
    add.add_argument('--ports', default='ANY')
    delete = commands.add_parser('delete')
    delete.add_argument('id')
    run = commands.add_parser('simulate')
    run.add_argument('--source', required=True)
    run.add_argument('--destination', required=True)
    run.add_argument('--protocol', required=True)
    run.add_argument('--port')
    batch = commands.add_parser('batch')
    batch.add_argument('file')
    args = parser.parse_args()
    try:
        if args.command == 'init':
            if Path(args.policy).exists():
                raise ValueError('Policy already exists; choose a new --policy path')
            save_policy(args.policy, json.loads((ROOT / 'examples/policy.json').read_text()))
            print(f'Created {args.policy}')
            return
        config = policy(json.loads(Path(args.policy).read_text()))
        if args.command == 'rules':
            print(json.dumps(config, indent=2))
        elif args.command in ('add', 'delete', 'default'):
            if args.command == 'add':
                config['rules'].append({k: getattr(args, k) for k in ('id', 'action', 'source', 'destination', 'protocol', 'ports')})
            elif args.command == 'delete':
                if args.id not in [r['id'] for r in config['rules']]:
                    raise ValueError('Rule ID not found')
                config['rules'] = [r for r in config['rules'] if r['id'] != args.id]
            else:
                config['default'] = args.action
            save_policy(args.policy, config)
            print('Policy saved')
        else:
            incoming = [vars(args)] if args.command == 'simulate' else json.loads(Path(args.file).read_text())
            if not isinstance(incoming, list):
                raise ValueError('Batch must be a JSON array')
            for item in incoming:
                print(json.dumps(simulate(config, item, args.log)))
    except (ValueError, KeyError, TypeError, OSError) as error:
        parser.exit(2, f'Error: {error}\n')


if __name__ == '__main__':
    main()
