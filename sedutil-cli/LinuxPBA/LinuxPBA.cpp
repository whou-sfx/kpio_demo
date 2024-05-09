/* C:B**************************************************************************
This software is Copyright 2014-2017 Bright Plaza Inc. <drivetrust@drivetrust.com>

    This file is part of sedutil.

    sedutil is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    sedutil is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with sedutil.  If not, see <http://www.gnu.org/licenses/>.

* C:E********************************************************************** */

#include <unistd.h>
#include <sys/reboot.h>
#include <iostream>
#include "log.h"
#include "GetPassPhrase.h"
#include "UnlockSEDs.h"

#ifdef PBA_NETWORKING_BUILD
#include "GetNetPassPhrase.h"
#endif

using namespace std;

/* Default to output that includes timestamps and goes to stderr*/
sedutiloutput outputFormat = sedutilNormal;

int main(int argc, char** argv) {

    CLog::Level() = CLog::FromInt(0);
    LOG(D4) << "Legacy PBA start" << endl;
    printf("\n\n Boot Authorization \n");

    std::shared_ptr<SecureString> p;
    uint8_t n_unlocks = 0, n_counter = 0;

    /* If networking is enabled, try getting the password via the network. */
#ifdef PBA_NETWORKING_BUILD
    while (n_unlocks == 0 && n_counter < 3) {
        p = GetNetPassPhrase();
        n_unlocks += UnlockSEDs((char *)p->c_str());
        if (n_unlocks == 0) n_counter++;
    }
    n_counter = 0;
#endif

    /* Otherwise ask for the unlock password via the console. */
    while (n_unlocks == 0 && n_counter < 3) {
        p = GetPassPhrase(" Password: ");
        n_unlocks += UnlockSEDs((char *)p->c_str());
        if (n_unlocks == 0) n_counter++;
    }

    if (n_counter >= 3) {
        printf("\n Authorization failed. Shutting down... \n");
        sync();
        reboot(RB_POWER_OFF);
    }
    else if (strcmp(p->c_str(), "debug")) {
        printf("\n Access granted. Starting the system... \n");
        sync();
        reboot(RB_AUTOBOOT);
    }

    return 0;
}
