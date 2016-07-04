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

import logging
import getpass
import optparse
import pprint
import sys

from reviewstats import utils


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
        '--projects-dir', default='./projects',
        help='Directory where to locate the project files')

    optparser.add_option(
        '--debug', action='store_true', help='Show extra debug output')

    optparser.add_option(
        '-u', '--user', default=getpass.getuser(), help='gerrit user')
    optparser.add_option(
        '-P', '--password', default=getpass.getuser(),
        help='gerrit HTTP password')
    optparser.add_option(
        '-k', '--key', default=None, help='ssh key for gerrit')
    optparser.add_option(
        '--server', default='review.openstack.org',
        help='Gerrit server to connect to')

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
                                server=options.server, cached_only=True)

    processed_changes = []
    for change in changes:

        merged_on = None
        abandoned_on = None
        is_open = change["open"]
        if not is_open:
            last_patchset = change["patchSets"][-1]
            last_patchset_approvals = last_patchset.get("approvals", [])
            merge_approvals = [approval
                for approval in last_patchset_approvals
                if approval["type"]== "SUBM"]
            if merge_approvals:
                merge_approval = merge_approvals[0]
                merged_on = merge_approval["grantedOn"]
            else:
                if change["status"] == "ABANDONED":
                    # TODO(johngarbutt) there must be a better way
                    abandoned_on = change["lastUpdated"]
                else:
                    pprint.pprint(change)
                    raise Exception("parse error - no merge")

        processed_changes.append({
            'created': change["createdOn"],
            'is_open': is_open,
            'status': change['status'],
            'closed_on': merged_on if merged_on else abandoned_on
        })

    pprint.pprint(processed_changes)
    print len(changes)
