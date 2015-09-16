# Copyright (C) 2011 - Soren Hansen
# Copyright (C) 2013 - Red Hat, Inc.
#

# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import calendar
import datetime
import getpass
import logging
import optparse
import re
import sys

from reviewstats import utils


def sec_to_period_string(seconds):
    days = seconds / (3600 * 24)
    hours = (seconds / 3600) - (days * 24)
    minutes = (seconds / 60) - (days * 24 * 60) - (hours * 60)
    return '%d days, %d hours, %d minutes' % (days, hours, minutes)


def average_age(changes, key='age'):
    if not changes:
        return 0
    total_seconds = 0
    for change in changes:
        total_seconds += change[key]
    avg_age = total_seconds / len(changes)
    return sec_to_period_string(avg_age)


def quartile_age(changes, quartile=2, key='age'):
    """Quartile age

    quartile 1: 25%
    quartile 2: 50% (median) default
    quartile 3: 75%
    """

    if not changes:
        return 0
    changes = sorted(changes, key=lambda change: change[key])
    quartile_age = changes[len(changes) * quartile / 4][key]
    return sec_to_period_string(quartile_age)


def number_waiting_more_than(changes, seconds, key='age'):
    index = 0
    for change in changes:
        if change[key] < seconds:
            return index
        index += 1
    return len(changes)


def format_url(url, options):
    return '%s%s%s' % ('<a href="' if options.html else '',
                       url,
                       ('">%s</a>' % url) if options.html else '')


def gen_stats(projects, waiting_on_reviewer, waiting_on_submitter,
              waiting_on_plus_two, options):
    age_sorted = sorted(waiting_on_reviewer,
                        key=lambda change: change['age'], reverse=True)
    age2_sorted = sorted(waiting_on_reviewer,
                         key=lambda change: change['age2'], reverse=True)
    age3_sorted = sorted(waiting_on_reviewer,
                         key=lambda change: change['age3'], reverse=True)
    age_submitter_sorted = sorted(waiting_on_submitter,
                        key=lambda change: change['age4'], reverse=True)
    age_plus_two_sorted = sorted(waiting_on_plus_two,
                        key=lambda change: change['age'], reverse=True)

    result = []
    result.append(('Projects', '%s' % [project['name']
                                       for project in projects]))
    stats = []
    stats.append(('Total Open Reviews', '%d'
                  % (len(waiting_on_reviewer) + len(waiting_on_submitter))))
    stats.append(('Waiting on Submitter', '%d' % len(waiting_on_submitter)))
    stats.append(('Waiting on Reviewer', '%d' % len(waiting_on_reviewer)))

    latest_rev_stats = []
    latest_rev_stats.append(('Average wait time', '%s'
                             % (average_age(waiting_on_reviewer))))
    latest_rev_stats.append(('1st quartile wait time', '%s'
                             % (quartile_age(waiting_on_reviewer,
                                             quartile=1))))
    latest_rev_stats.append(('Median wait time', '%s'
                             % (quartile_age(waiting_on_reviewer))))
    latest_rev_stats.append(('3rd quartile wait time', '%s'
                             % (quartile_age(waiting_on_reviewer,
                                             quartile=3))))
    latest_rev_stats.append((
        'Number waiting more than %i days' % options.waiting_more,
        '%i' % (number_waiting_more_than(
            age_sorted, 60 * 60 * 24 * options.waiting_more))))
    stats.append(('Stats since the latest revision', latest_rev_stats))

    last_without_nack_stats = []
    last_without_nack_stats.append(('Average wait time', '%s'
                                    % (average_age(waiting_on_reviewer,
                                                   key='age3'))))
    last_without_nack_stats.append(('1st quartile wait time', '%s'
                                    % (quartile_age(waiting_on_reviewer,
                                                    quartile=1,
                                                    key='age3'))))
    last_without_nack_stats.append(('Median wait time', '%s'
                                    % (quartile_age(waiting_on_reviewer,
                                                    key='age3'))))
    last_without_nack_stats.append(('3rd quartile wait time', '%s'
                                    % (quartile_age(waiting_on_reviewer,
                                                    quartile=3,
                                                    key='age3'))))
    last_without_nack_stats.append((
        'Number waiting more than %i days' % options.waiting_more,
        '%i' % (number_waiting_more_than(
            age3_sorted, 60 * 60 * 24 * options.waiting_more))))
    stats.append(('Stats since the last revision without -1 or -2 ',
                 last_without_nack_stats))

    first_rev_stats = []
    first_rev_stats.append(('Average wait time', '%s'
                            % (average_age(waiting_on_reviewer, key='age2'))))
    first_rev_stats.append(('1st quartile wait time', '%s'
                            % (quartile_age(waiting_on_reviewer, quartile=1,
                                            key='age2'))))
    first_rev_stats.append(('Median wait time', '%s'
                            % (quartile_age(waiting_on_reviewer, key='age2'))))
    first_rev_stats.append(('3rd quartile wait time', '%s'
                            % (quartile_age(waiting_on_reviewer, quartile=3,
                                            key='age2'))))
    first_rev_stats.append((
        'Number waiting more than %i days' % options.waiting_more,
        '%i' % (number_waiting_more_than(
            age2_sorted, 60 * 60 * 24 * options.waiting_more))))
    stats.append(('Stats since the first revision (total age)',
                  first_rev_stats))

    waiting_after_neg_stats = []
    waiting_after_neg_stats.append(('Average wait time', '%s'
                            % (average_age(waiting_on_submitter,
                                           key='age4'))))
    waiting_after_neg_stats.append(('1st quartile wait time', '%s'
                            % (quartile_age(waiting_on_submitter, quartile=1,
                                            key='age4'))))
    waiting_after_neg_stats.append(('Median wait time', '%s'
                            % (quartile_age(waiting_on_submitter,
                                            key='age4'))))
    waiting_after_neg_stats.append(('3rd quartile wait time', '%s'
                            % (quartile_age(waiting_on_submitter, quartile=3,
                                            key='age4'))))
    waiting_after_neg_stats.append((
        'Number waiting more than %i days' % options.waiting_more,
        '%i' % (number_waiting_more_than(
            age_submitter_sorted, 60 * 60 * 24 * options.waiting_more))))
    stats.append(('Stats since last negative vote on current patch',
                  waiting_after_neg_stats))

    changes = []
    for change in age_sorted[:options.longest_waiting]:
        changes.append('%s %s (%s) had +2: %s' % (sec_to_period_string(change['age']),
                                       format_url(change['url'], options),
                                       change['subject'],
                                       change["previous_plus_two"]))
    stats.append(('Longest waiting reviews (based on latest revision)',
                 changes))

    changes = []
    for change in age3_sorted[:options.longest_waiting]:
        changes.append('%s %s (%s) had +2: %s' % (sec_to_period_string(change['age3']),
                                       format_url(change['url'], options),
                                       change['subject'],
                                       change["previous_plus_two"]))
    stats.append(('Longest waiting reviews (based on oldest rev without -1 or'
                 ' -2)', changes))

    changes = []
    for change in age2_sorted[:options.longest_waiting]:
        changes.append('%s %s (%s) had +2: %s' % (sec_to_period_string(change['age2']),
                                       format_url(change['url'], options),
                                       change['subject'],
                                       change["previous_plus_two"]))
    stats.append(('Oldest reviews (time since first revision)',
                  changes))

    changes = []
    for change in age_submitter_sorted[:options.longest_waiting]:
        changes.append('%s %s (%s) had +2: %s' % (
                                       sec_to_period_string(change['age4']),
                                       format_url(change['url'], options),
                                       change['subject'],
                                       change["previous_plus_two"]))
    stats.append(('Longest stuck reviews (time since current -1'
                  ' or -2 vote)', changes))

    changes = []
    for change in age_plus_two_sorted:
        changes.append('%s %s (%s)' % (sec_to_period_string(change['age']),
                                       format_url(change['url'], options),
                                       change['subject']))
    stats.append(('Waiting for one more plus two (based on latest revision)',
                  changes))

    # TODO - need to add stats summary
    has_blueprint = [change for change in waiting_on_reviewer \
                     if change['blueprint']]
    blueprints = {}
    for change in has_blueprint:
        blueprints_key = change['blueprint']
        if blueprints_key not in blueprints:
            blueprints[blueprints_key] = change
            change["patches"] = 1
        else:
            old_change = blueprints[blueprints_key]
            old_change["patches"] += 1
            if change['age2'] > old_change['age2']:
                # pick the oldest change, if there are multiple
                blueprints[blueprints_key] = change
                change["patches"] = old_change["patches"]

    since_blueprint_patch_started = sorted(blueprints.values(),
                         key=lambda change: change['age2'], reverse=True)

    changes = []
    for change in since_blueprint_patch_started:
        blueprint_url = "https://blueprints.launchpad.net/nova/+spec/%s"
        changes.append('%s %s (%s %s patches: %s, had +2: %s)' %
                (sec_to_period_string(change['age2']),
                 format_url(change['url'], options),
                 change['subject'],
                 format_url(blueprint_url % change['blueprint'], options),
                 change["patches"],
                 change["previous_plus_two"]))
    stats.append(('Oldest blueprint patches waiting for a review (time since first revision)',
                  changes))

    # TODO - worst cut and paste job EVER!
    tag = 'bug'
    has_blueprint = [change for change in waiting_on_reviewer \
                     if change[tag]]
    blueprints = {}
    for change in has_blueprint:
        blueprints_key = change[tag]
        if blueprints_key not in blueprints:
            blueprints[blueprints_key] = change
            change["patches"] = 1
        else:
            old_change = blueprints[blueprints_key]
            old_change["patches"] += 1
            if change['age2'] > old_change['age2']:
                # pick the oldest change, if there are multiple
                blueprints[blueprints_key] = change
                change["patches"] = old_change["patches"]
    since_blueprint_patch_started = sorted(blueprints.values(),
                         key=lambda change: change['age2'], reverse=True)
    changes = []
    for change in since_blueprint_patch_started:
        blueprint_url = "https://bugs.launchpad.net/nova/+bug/%s"
        changes.append('%s %s (%s %s patches: %s, had +2: %s)' %
                (sec_to_period_string(change['age2']),
                 format_url(change['url'], options),
                 change['subject'],
                 format_url(blueprint_url % change[tag], options),
                 change["patches"],
                 change["previous_plus_two"]))
    stats.append(('Oldest %s patches waiting for a review (time since first revision)' % tag,
                  changes))

    # TODO - worst cut and paste job EVER! x 200
    tag = 'bug'
    has_blueprint = [change for change in waiting_on_submitter \
                     if change[tag]]
    blueprints = {}
    for change in has_blueprint:
        blueprints_key = change[tag]
        if blueprints_key not in blueprints:
            blueprints[blueprints_key] = change
            change["patches"] = 1
        else:
            old_change = blueprints[blueprints_key]
            old_change["patches"] += 1
            if change['age2'] > old_change['age2']:
                # pick the oldest change, if there are multiple
                blueprints[blueprints_key] = change
                change["patches"] = old_change["patches"]
    since_blueprint_patch_started = sorted(blueprints.values(),
                         key=lambda change: change['age2'], reverse=True)
    changes = []
    for change in since_blueprint_patch_started:
        blueprint_url = "https://bugs.launchpad.net/nova/+bug/%s"
        changes.append('%s %s (%s %s patches: %s, had +2: %s)' %
                (sec_to_period_string(change['age2']),
                 format_url(change['url'], options),
                 change['subject'],
                 format_url(blueprint_url % change[tag], options),
                 change["patches"],
                 change["previous_plus_two"]))
    stats.append(('Oldest %s stuck patches (time since first revision)' % tag,
                  changes))

    # TODO - worst cut and paste job EVER! x 10000
    tag = 'previous_plus_two'
    had_plus_two = [change for change in waiting_on_submitter \
                     if change[tag]]
    since_blueprint_patch_started = sorted(had_plus_two,
                         key=lambda change: change['age2'], reverse=True)
    changes = []
    for change in since_blueprint_patch_started:
        blueprint_url = "https://bugs.launchpad.net/nova/+bug/%s"
        changes.append('%s %s (%s %s)' %
                (sec_to_period_string(change['age2']),
                 format_url(change['url'], options),
                 change['subject'],
                 format_url(blueprint_url % change[tag], options)))
    stats.append(('Oldest stuck patches with previous +2 (time since first revision)',
                 changes))

    result.append(stats)
    return result


def print_stats_txt(stats, f=sys.stdout):
    def print_list_txt(l, level):
        for item in l:
            if not isinstance(item, list):
                f.write('%s> ' % ('--' * level))
            print_item_txt(item, level)

    def print_item_txt(item, level):
        if isinstance(item, basestring):
            f.write('%s\n' % item.encode('utf-8'))
        elif isinstance(item, list):
            print_list_txt(item, level + 1)
        elif isinstance(item, tuple):
            f.write('%s: ' % item[0])
            if isinstance(item[1], list):
                f.write('\n')
            print_item_txt(item[1], level)
        else:
            raise Exception('Unhandled type')

    print_list_txt(stats, 0)


def print_stats_html(stats, f=sys.stdout):
    def print_list_html(l, level):
        if level:
            f.write('<%s>\n' % ('ul' if level == 1 else 'ol'))
        for item in l:
            if level:
                f.write('%s<li>' % ('  ' * level))
            print_item_html(item, level)
            if level:
                f.write('</li>\n')
        if level:
            f.write('</%s>\n' % ('ul' if level == 1 else 'ol'))

    def print_item_html(item, level):
        if isinstance(item, basestring):
            f.write('%s' % item.encode('utf-8'))
        elif isinstance(item, list):
            print_list_html(item, level + 1)
        elif isinstance(item, tuple):
            f.write('%s: ' % item[0])
            if isinstance(item[1], list):
                f.write('\n')
            print_item_html(item[1], level)
        else:
            raise Exception('Unhandled type')

    f.write('<html>\n')
    f.write('<head><title>Open Reviews for %s</title></head>\n' % stats[0][1])
    print_list_html(stats, 0)
    f.write('</html>\n')


def find_oldest_no_nack(change):
    last_patch = None
    for patch in reversed(change['patchSets']):
        nacked = False
        for review in patch.get('approvals', []):
            if review['value'] in ('-1', '-2'):
                nacked = True
                break
        if nacked:
            break
        last_patch = patch
    return last_patch


#taken from jeepyb
SPEC_RE = re.compile(r'\b(blueprint|bp)\b[ \t]*[#:]?[ \t]+(\S+)', re.I)


def get_blueprints(message):
    #taken from jeepyb
    bps = set([m.group(2) for m in SPEC_RE.finditer(message)])
    return list(bps)


def extract_blueprint(change):
    msg = change.get('commitMessage')
    if msg is not None:
        bps = get_blueprints(msg)
        if len(bps) > 0:
            bp = max(bps, key=lambda x: len(x))
            return bp


def get_bug(message):
    part1 = r'^[\t ]*(?P<prefix>[-\w]+)?[\s:]*'
    part2 = r'(?:\b(?:bug|lp)\b[\s#:]*)+'
    part3 = r'(?P<bug_number>\d+)\s*?$'
    regexp = part1 + part2 + part3
    matches = re.finditer(regexp, message, flags=re.I | re.M)
    for match in matches:
        prefix = match.group('prefix')
        bug_num = match.group('bug_number')
        # TODO what if its for two bugs? meh
        return bug_num


def extract_bug(change):
    msg = change.get('commitMessage')
    if msg is not None:
        return get_bug(msg)


def has_previous_plus_two(change):
    patch_sets = change['patchSets']
    for patch_set in patch_sets:
        approvals = patch_set.get('approvals', [])
        for review in approvals:
            if review['value'] in ('+2'):
                return True
    return False


def main(argv=None):
    if argv is None:
        argv = sys.argv

    optparser = optparse.OptionParser()
    optparser.add_option(
        '-p', '--project', default='projects/nova.json',
        help='JSON file describing the project to generate stats for')
    optparser.add_option(
        '-a', '--all', action='store_true',
        help='Generate stats across all known projects (*.json)')
    optparser.add_option(
        '-u', '--user', default=getpass.getuser(), help='gerrit user')
    optparser.add_option(
        '-k', '--key', default=None, help='ssh key for gerrit')
    optparser.add_option(
        '-s', '--stable', action='store_true',
        help='Include stable branch commits')
    optparser.add_option(
        '-l', '--longest-waiting', type='int', default=5,
        help='Show n changesets that have waited the longest)')
    optparser.add_option(
        '-m', '--waiting-more', type='int', default=7,
        help='Show number of changesets that have waited more than n days)')
    optparser.add_option(
        '-H', '--html', action='store_true',
        help='Use HTML output instead of plain text')
    optparser.add_option(
        '--server', default='review.openstack.org',
        help='Gerrit server to connect to')
    optparser.add_option(
        '--debug', action='store_true', help='Show extra debug output')
    optparser.add_option(
        '--projects-dir', default='./projects',
        help='Directory where to locate the project files')
    optparser.add_option(
        '--output', '-o', default='-',
        help="Where to write output. - for stdout. The file will be appended"
             " if it exists.")

    options, args = optparser.parse_args()

    logging.basicConfig(level=logging.ERROR)
    if options.debug:
        logging.root.setLevel(logging.DEBUG)

    projects = utils.get_projects_info(options.project, options.all,
                                       base_dir=options.projects_dir)

    if not projects:
        print "Please specify a project."
        sys.exit(1)

    changes = utils.get_changes(projects, options.user, options.key,
                                only_open=True, server=options.server)

    waiting_on_submitter = []
    waiting_on_reviewer = []
    waiting_on_plus_two = []

    now = datetime.datetime.utcnow()
    now_ts = calendar.timegm(now.timetuple())

    for change in changes:
        if 'rowCount' in change:
            continue
        if not options.stable and 'stable' in change['branch']:
            continue
        if utils.is_workinprogress(change):
            # Filter out WORKINPROGRESS
            continue
        latest_patch = change['patchSets'][-1]
        if utils.patch_set_approved(latest_patch):
            # Ignore patches already approved and just waiting to merge
            continue
        waiting_for_review = True
        approvals = latest_patch.get('approvals', [])
        approvals.sort(key=lambda a: a['grantedOn'])
        age_of_latest_nack = None
        has_plus_two = False
        for review in approvals:
            if review['value'] in ('+2'):
                has_plus_two = True
            if review['type'] not in ('CRVW', 'VRIF',
                                      'Code-Review', 'Verified'):
                continue
            if review['value'] in ('-1', '-2'):
                waiting_for_review = False
                has_plus_two = False
                age_of_latest_nack = now_ts - review['grantedOn']
                break

        change['age'] = utils.get_age_of_patch(latest_patch, now_ts)
        change['age2'] = utils.get_age_of_patch(change['patchSets'][0], now_ts)
        patch = find_oldest_no_nack(change)
        change['age3'] = utils.get_age_of_patch(patch, now_ts) if patch else 0
        change['age4'] = age_of_latest_nack
        change['blueprint'] = extract_blueprint(change)
        change['bug'] = extract_bug(change)
        change['has_plus_two'] = has_plus_two
        change['previous_plus_two'] = has_previous_plus_two(change)

        if has_plus_two:
            waiting_on_plus_two.append(change)
        if waiting_for_review:
            waiting_on_reviewer.append(change)
        else:
            waiting_on_submitter.append(change)

    stats = gen_stats(projects, waiting_on_reviewer, waiting_on_submitter,
                      waiting_on_plus_two, options)

    if options.output == '-':
        output = sys.stdout
    else:
        output = open(options.output, 'at')
    try:
        if options.html:
            print_stats_html(stats, f=output)
        else:
            print_stats_txt(stats, f=output)
    finally:
        if output is not sys.stdout:
            output.close()
