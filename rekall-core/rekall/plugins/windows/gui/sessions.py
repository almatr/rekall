# Rekall Memory Forensics
# Copyright (C) 2007,2008 Volatile Systems
# Copyright (C) 2010,2011,2012 Michael Hale Ligh <michael.ligh@mnin.org>
# Copyright 2013 Google Inc. All Rights Reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

# pylint: disable=protected-access

# References:
# http://volatility-labs.blogspot.ch/2012/09/movp-11-logon-sessions-processes-and.html
# Windows Internals 5th Edition. Chapter 9.


from rekall import obj
from rekall.plugins.windows import common


class Sessions(common.WinProcessFilter):
    """List details on _MM_SESSION_SPACE (user logon sessions).

    Windows uses sessions in order to separate processes. Sessions are used to
    separate the address spaces of windows processes.

    Note that this plugin traverses the ProcessList member of the session object
    to list the processes - yet another list _EPROCESS objects are on.
    """

    __name = "sessions"

    def session_spaces(self):
        """Generates unique _MM_SESSION_SPACE objects.

        Generates unique _MM_SESSION_SPACE objects referenced by active
        processes.

        Yields:
          _MM_SESSION_SPACE instantiated from the session space's address space.
        """
        # Dedup based on sessions.
        seen = set()
        for proc in self.filter_processes():
            ps_ad = proc.get_process_address_space()

            session = proc.Session
            # Session pointer is invalid (e.g. for System process).
            if not session:
                continue

            if session in seen:
                continue

            seen.add(session)

            yield proc.Session.deref(vm=ps_ad)

    def find_session_space(self, session_id):
        """Get a _MM_SESSION_SPACE object by its ID.

        Args:
          session_id: the session ID to find.

        Returns:
          _MM_SESSION_SPACE instantiated from the session space's address space.
        """
        for session in self.session_spaces():
            if session.SessionId == session_id:
                return session

        return obj.NoneObject("Cannot locate a session %s", session_id)

    def render(self, renderer):
        for session in self.session_spaces():
            renderer.section()

            processes = list(session.ProcessList.list_of_type(
                "_EPROCESS", "SessionProcessLinks"))

            renderer.format("Session(V): {0:addrpad} ID: {1} Processes: {2}\n",
                            session.obj_offset,
                            session.SessionId,
                            len(processes))

            renderer.format(
                "PagedPoolStart: {0:addrpad} PagedPoolEnd {1:addrpad}\n",
                session.PagedPoolStart,
                session.PagedPoolEnd)

            for process in processes:
                renderer.format(" Process: {0} @ {1}\n",
                                process,
                                process.CreateTime)

            # Follow the undocumented _IMAGE_ENTRY_IN_SESSION list to find the
            # kernel modules loaded in this session.
            for image in session.ImageIterator:
                symbol = self.session.address_resolver.format_address(
                    image.ImageBase)

                renderer.format(
                    " Image: {0:addrpad}, Address {1:addrpad}, Name: {2}\n",
                    image.obj_offset,
                    image.ImageBase,
                    symbol)
