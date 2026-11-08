/* ugprobe: usergroup.library (Roadshow's, LIBS:) on whatever
   bsdsocket.library is installed: ids, the user and group databases
   (DEVS:Internet/users, groups), crypt, getlogin, and the library's
   status of its own.

   Build (from the repository root):
     docker run --rm -v "$PWD":/w -w /w walkero/amigagccondocker:os4-gcc11 \
       ppc-amigaos-gcc -O2 -Wall -I/opt/ppc-amigaos/ppc-amigaos/SDK/include/netinclude \
       -o testprogs/rstcp/c/ugprobe testprogs/rstcp/c/ugprobe.c */

#include <proto/exec.h>
#include <proto/usergroup.h>
#include <libraries/usergroup.h>
#include <stdio.h>

struct Library *UserGroupBase;
struct UserGroupIFace *IUserGroup;

int main(void)
{
	struct passwd *pw;
	struct group *gr;
	int n;

	UserGroupBase = IExec->OpenLibrary("usergroup.library", 4);
	printf("usergroup.library %s", UserGroupBase ? "opened" : "did not open\n");
	if (UserGroupBase == NULL)
		return 20;
	printf(" (version %d.%d)\n", UserGroupBase->lib_Version, UserGroupBase->lib_Revision);
	IUserGroup = (struct UserGroupIFace *)IExec->GetInterface(UserGroupBase, "main", 1, NULL);
	if (IUserGroup == NULL) {
		printf("no main interface\n");
		IExec->CloseLibrary(UserGroupBase);
		return 20;
	}
	printf("uid %ld euid %ld gid %ld egid %ld login %s\n", (long)IUserGroup->getuid(), (long)IUserGroup->geteuid(),
		(long)IUserGroup->getgid(), (long)IUserGroup->getegid(), IUserGroup->getlogin() ? (char *)IUserGroup->getlogin() : "(none)");
	pw = IUserGroup->getpwuid(0);
	printf("getpwuid(0): %s\n", pw ? (char *)pw->pw_name : "(none)");
	pw = IUserGroup->getpwnam((STRPTR)"root");
	printf("getpwnam(root): %s uid %ld gid %ld dir %s shell %s\n", pw ? (char *)pw->pw_name : "(none)",
		pw ? (long)pw->pw_uid : -1L, pw ? (long)pw->pw_gid : -1L, pw ? (char *)pw->pw_dir : "", pw ? (char *)pw->pw_shell : "");
	IUserGroup->setpwent();
	for (n = 0; (pw = IUserGroup->getpwent()) != NULL && n < 20; n++)
		printf("  user %s %ld\n", (char *)pw->pw_name, (long)pw->pw_uid);
	IUserGroup->endpwent();
	IUserGroup->setgrent();
	for (n = 0; (gr = IUserGroup->getgrent()) != NULL && n < 20; n++)
		printf("  group %s %ld\n", (char *)gr->gr_name, (long)gr->gr_gid);
	IUserGroup->endgrent();
	printf("crypt: %s\n", (char *)IUserGroup->crypt((UBYTE *)"secret", (UBYTE *)"ab"));
	printf("ug_GetErr %ld (%s)\n", (long)IUserGroup->ug_GetErr(), (char *)IUserGroup->ug_StrError(IUserGroup->ug_GetErr()));
	IExec->DropInterface((struct Interface *)IUserGroup);
	IExec->CloseLibrary(UserGroupBase);
	return 0;
}
