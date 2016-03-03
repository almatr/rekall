# This file is part of Rekall Memory Forensics.
# Copyright (C) 2007-2013 Volatility Foundation
# Copyright 2013 Google Inc. All Rights Reserved.
#
# Rekall Memory Forensics is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License Version 2 as
# published by the Free Software Foundation.  You may not use, modify or
# distribute this program under any other version of the GNU General
# Public License.
#
# Rekall Memory Forensics is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Rekall Memory Forensics.  If not, see <http://www.gnu.org/licenses/>.
#

"""
@author:       Andrew Case
@license:      GNU General Public License 2.0
@contact:      atcuno@gmail.com
@organization:
"""

from rekall.plugins.linux import common

class PSTreeObject(object):
    def __init__(self, pstree, sort_order):
        self.pstree = pstree
        self.sort_order = sort_order
  
    def getPSTree(self):
        return self.pstree

    def __lt__(self, other):
        if self.pstree[self.sort_order] < other.pstree[self.sort_order]:
            return True
        elif self.pstree[self.sort_order] > other.pstree[self.sort_order]:
            return False
        else:
          return self.pstree[0] < other.pstree[0]

    def __eq__(self, other):
        return (self.pstree[self.sort_order] == other.pstree[self.sort_order])

class LinPSTree(common.LinuxPlugin):
    """Shows the parent/child relationship between processes.

    This plugin prints a parent/child relationship tree by walking the
    task_struct.children and task_struct.sibling members.
    """
    __name = "pstree"

    @classmethod
    def args(cls, parser):
        """Declare the command line args we accept."""
        parser.add_argument(
            "sort_order", default=0, help="Sort order.")
        super(LinPSTree, cls).args(parser)

    def __init__(self, sort_order=0, **kwargs):
        super(LinPSTree, self).__init__(**kwargs)
        self.sort_order = sort_order

    def render(self, renderer):
        renderer.table_header([("Pid", "pid", ">6"),
			       ("Ppid", "ppid", ">6"),
			       ("Uid", "uid", ">6"),
			       ("", "depth", "0"),
			       ("Name", "name", "<30"),])

        root_task = self.profile.get_constant_object(
            "init_task", target="task_struct")

        sorted_list = []
        for task, level in self.recurse_task(root_task, 0):
            sorted_list.append(PSTreeObject(
                [task.pid, task.parent.pid, task.uid, "." * level, task.commandline], self.sort_order))

        sorted_list.sort()
        for PSTree in sorted_list:
            renderer.table_row(*PSTree.getPSTree())

    def recurse_task(self, task, level):
        """Yields all the children of this task."""
        yield task, level

        for child in task.children.list_of_type("task_struct", "sibling"):
            for subtask, sublevel in self.recurse_task(child, level + 1):
                yield subtask, sublevel

