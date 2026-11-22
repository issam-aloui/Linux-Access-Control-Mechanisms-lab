---
title: "TP 2: Access Control"
course: Computer Systems Security
date: 2026-11-07
---

# TP 2: Access Control

University of Blida 1  
Computer Science Department  
4th year Engineering

## Part 0: Setup and users

### Q1. User database

(a) Bob's line is `bob:x:1005:1005::/home/bob:/bin/bash`: name `bob`, password placeholder `x`, UID 1005, primary GID 1005 (group `bob`), empty comment field, home `/home/bob`, login shell `/bin/bash`. His supplementary groups `users` (100) and `analyst` (1002) are listed in `/etc/group`, not in this line.

(b) The `x` means the password hash is in `/etc/shadow`. That file is `-rw-r----- root shadow`, so root and the `shadow` group can read it.

(c) Every process needs `/etc/passwd` to turn a UID into a user name, a home directory and a login shell.

(d) `/home/alice` is `drwxr-x--- alice alice` (750): Alice has rwx, the `alice` group has r-x, other has nothing.

![Figure 1](<pictures/image-01.png>)

*Figure 1. User entries, Bob's groups, and the permissions on the password files and home directories.*

## Part 1: DAC

### Q2. Alice's secret file

Prediction: the directory stops t4l3nt before he reaches the file.

(a) `/home/alice` is 750 and t4l3nt is neither Alice nor in group `alice`, so he has no `x` on the directory and cannot reach the inode. `namei -l` shows whether the failure is on the path or on the file.

(b) The file's mode blocks him now. After `chmod 755 /home/alice`, t4l3nt can traverse the directory, but `secret.txt` is `-rw------- alice alice`, so only Alice can read it.

![Figure 2](<pictures/Screenshot 2026-11-07 164125.png>)

*Figure 2. The first denial, the `namei` path, and the second denial after `/home/alice` was set to 755.*

### Q3. Bob's five attempts

(a)

```text
cat: /home/alice/secret.txt: Permission denied
grep: /home/alice/secret.txt: Permission denied
bash: line 1: /home/alice/secret.txt: Permission denied
ln: failed to create symbolic link '/tmp/shortcut': File exists
chmod: changing permissions of '/home/alice/secret.txt': Operation not permitted
```

(b) The kernel checks the target inode's 600 mode in every case. `cat`, `grep`, the shell redirection and the symlink are only different ways to reach the file, and a symlink has no permissions of its own. `/tmp/shortcut` already existed from an earlier attempt, so `ln` failed with `File exists`; after removing it, `cat /tmp/shortcut` is still denied.

(c) Bob cannot change the mode of a file he does not own. Only Alice, the owner, or root can.

(d) It makes the file readable by every account. Malware running as Alice can already read it, so the added risk is that any other compromised account or service can read it too.

![Figure 3](<pictures/Screenshot 2026-11-07 164841.png>)

*Figure 3. Bob's read attempts and the refused `chmod`.*

### Q4. A file Alice owns but cannot read

(a)

| User | Predicted | Observed |
|---|---|---|
| alice | N | N, permission denied |
| bob | Y | Y, `Board notes` |
| t4l3nt | Y | Y, `Board notes` |

(b) Linux uses the first class that matches. Alice is the owner, so only the owner bits apply and they are `---`. Bob matches the group `analyst` (`rw-`) and t4l3nt matches other (`r--`). Alice can fix it with `chmod u+r`; root can too, but no other user can.

![Figure 4](<pictures/Screenshot 2026-11-07 192558.png>)

*Figure 4. The file is readable by the group and by other, but not by its owner.*

### Q5. The SOC shared folder

Prediction: Charlie can read `report2.txt` after `g+s` because the group becomes `analyst`, but he cannot delete it because the file is 440. After `+t`, he cannot delete `report3.txt` either.

(a) `report.txt` was created before `g+s` with umask 007, giving 660 and group `bob` (Bob's primary group). Charlie is not in `bob` and other has no rights, so `cat` is denied. `g+s` makes new files inherit the directory's group `analyst`; it does not change `report.txt`. `report2.txt` is `bob:analyst`, so Charlie can read it.

(b) Deleting a file depends on write and execute on the parent directory, not on the file's mode. Charlie has rwx on `/srv/acme/soc` through `analyst`, so he can unlink `report2.txt` although he cannot write it. I predicted that the 440 mode would block deletion; it does not, because the directory permission decides. The sticky bit restricts deletion to the file owner, the directory owner or root; `/tmp` uses it. `T` in `drwxrws--T` means the sticky bit is set but other has no execute permission.

![Figure 5](<pictures/Screenshot 2026-11-07 192802.png>)

*Figure 5. Group inheritance, file deletion, and the sticky bit.*

### Q6. Which permission class applies

Second option: Linux takes the first class that matches (owner, then group, then other) and looks only at that one.

## Part 2: ACLs and the mask

### Q7. Sharing one file with Mark

Prediction: Mark is denied because `/home/mike` is 700 and he cannot traverse it.

(a) `x` on `/home/mike` lets Mark traverse the directory to reach the file; `r` alone would only let him list names. The `+` after the mode means the file has an extended ACL.

![Figure 6](<pictures/Screenshot 2026-11-07 194150.png>)

*Figure 6. Mark gets traverse on the directory and read on the file through ACLs.*

### Q8. Closing the file again

(a) Prediction: no. `chmod 000` sets the mask to `---`, and the mask limits the named entry.

(b)

```text
----------+ 1 mike mike 9 Nov 7 18:41 /home/mike/aclfile.txt

user::---
user:mark:r--    #effective:---
group::---
mask::---
other::---

cat: /home/mike/aclfile.txt: Permission denied
```

`#effective:---` means Mark's entry still exists but the mask removes it.

(c) No. The mask is the upper bound for named users, named groups and the group class. On a file with an ACL, `chmod`'s group bits set the mask, so `chmod 000` writes `mask::---`; it does not edit the `group::` entry.

(d) `setfacl -m m::r` sets the mask back to `r--`, so Mark's existing entry works again. Mike still cannot read: the mask grants the owner nothing, and `user::---` is empty. He needs `chmod u+r` or `setfacl -m u::r`.

![Figure 7](<pictures/Screenshot 2026-11-07 194207.png>)

*Figure 7. The mask is cleared, Mark's entry is cut to `---`, and the read is refused.*

### Q9. Mark as auditor

Prediction: Mark can read `report4.txt` but cannot append to it.

(a) The default ACL gives Mark `r-x`, but the new file is created with mode 0666. The inherited mask is taken from the file's group bits, so it becomes `rw-`; the `x` is cut and `#effective` shows `r--`. `cat` works, but the shell's append redirection needs `w`, which Mark does not have.

(b) Advantage: one user gets access to one file or directory without changing groups or ownership, and a default ACL applies the rule to new files. Risk: the mask can silently remove permissions, and a default ACL can grant access to files created later. To list files that have an ACL: `getfacl -R -s -p /`. `-s` skips files without an ACL and `-p` keeps absolute paths.

![Figure 8](<pictures/Screenshot 2026-11-07 194226.png>)

*Figure 8. The inherited ACL on `report4.txt` and the refused append.*

### Q10. ACL entry then `chmod 000`

Second option: he loses it, because `chmod` changes the mask and the mask limits every named entry.

## Part 3: Roles with sudo

### Q11. The analyst and auditor roles

(a) Prediction matched the observed table.

| Action | bob | charlie | mark | t4l3nt |
|---|---|---|---|---|
| `sudo journalctl -u ssh --no-pager` | Y | Y | N | N |
| `sudo journalctl -u ssh` | N | N | N | N |
| `sudo useradd evil` | N | N | N | N |
| `journalctl -u ssh --no-pager` (no sudo) | N | N | Y | N |

(b) The loop matched the table. Mark is the one surprise: `sudo journalctl` is refused, but plain `journalctl` works because the `systemd-journal` group gives him read access to the journal. The sudo log showed the accepted and refused commands.

(c) The arguments limit the rule to the ssh unit. If the rule allowed `/usr/bin/journalctl` alone, the same user could read every journal and use any option the binary supports. A sudo rule grants the program's full capability, not just the intended use.

(d) Mark's group access is persistent: it covers the whole journal, not only ssh, and reading it is not a sudo event. Removing it means editing group membership and having Mark log in again. Bob's sudo access is limited to one exact command and every use is logged; removing it means editing `/etc/sudoers.d/analyst`. The group is broader and easier to forget; sudo is narrower and auditable.

![Figure 9](<pictures/Screenshot 2026-11-07 194257.png>)

*Figure 9. The `analyst` command alias and the sudoers rule.*

### Q12. Why RBAC is easier to review

First option: rights follow the job, so reading one role and its members tells you who can do what.

## Part 4: MAC with AppArmor

The VM had the AppArmor module loaded but the AppArmor filesystem was not mounted. `apparmor_parser` could not load the profile, so the tests below show DAC only.

### Q13. A copy of `cat`

(a) DAC refused it. `/etc/shadow` is 640 `root:shadow`, and Bob is neither root nor in `shadow`. No AppArmor profile was loaded, so MAC was not involved.

(b) Root's `labcat` prints the shadow hash. That shows DAC lets root through and no MAC profile restricts the program. It is the baseline, because a MAC test only means something when root is also refused.

![Figure 10](<pictures/Screenshot 2026-11-07 194317.png>)

*Figure 10. Bob is refused by DAC, while root can read `/etc/shadow` with the copy.*

### Q14. The `labcat` profile

(a) Both `/etc/sudoers` and `/etc/shadow` were readable in complain mode, and also in enforce mode. Nothing was logged: `journalctl -k` said `No journal files were found`. For `/etc/shadow` the output was the root hash line.

```text
root:$y$j9T$...:20764:0:99999:7:::
No journal files were found.
```

`apparmor_parser` reported `interface file missing` and `aa-status` said the filesystem was not mounted, so the profile never loaded.

(b) There is no DENIED line to dissect, because the profile never loaded. On a working AppArmor the line would name `profile="labcat"`, `operation="open"`, `name="/etc/shadow"`, `requested_mask="r"`, `denied_mask="r"` and `fsuid=0`. Root's DAC check passes, but the profile denies the open, so MAC is the layer that says no.

(c) `sudo cat /etc/shadow` still works. AppArmor confines programs, not users: `labcat` has a profile, `cat` does not. Root can use any unconfined program.

(d) Without `audit`, the deny still denies but writes no audit record. In this VM nothing changed because AppArmor was not mounted, so there were no DENIED lines either way. If you rely on logs, a silent deny leaves no trace of the attempt.

![Figure 11](<pictures/Screenshot 2026-11-07 194423.png>)

*Figure 11. The profile load fails, and both files are still readable in complain and enforce mode.*

![Figure 12](<pictures/Screenshot 2026-11-07 194431.png>)

*Figure 12. The remaining enforce-mode reads and the empty AppArmor log filter.*

### Q15. Which sentence about MAC is correct

Second option: MAC is an extra check made after DAC, and access works only if both allow it.

### Q16. MAC systems and policy styles

Three systems with MAC built in: SELinux (Android, RHEL), AppArmor (Ubuntu, SUSE) and Windows Mandatory Integrity Control. AppArmor is path-based, so its profiles are simple to read and write; a file can still be reached through another path or a hard link. SELinux is label-based, so a rename or move does not change the policy; it is more precise but harder to administer.

## Part 5: Who said no?

### Q17. The five cases

| Case | Symptom | Layer | Command used | Fix / do not |
|---|---|---|---|---|
| A | bob cannot read `/srv/acme/vault/plan.txt`, but `ls -l` shows `-rw-r--r--` | Path (directory) | `namei -l /srv/acme/vault/plan.txt`; `ls -ld /srv/acme/vault` | Give bob `x` on the directory (ACL `u:bob:x` or a group), not read. Do not chmod 777 the file or the directory. |
| B | bob cannot read `/srv/acme/payroll.txt`, but `getfacl` has an entry that gives him `r` | ACL mask | `getfacl /srv/acme/payroll.txt` | Set the mask to include r: `setfacl -m m::r`. Do not delete the ACL entry or chmod 777. |
| C | alice cannot read her own `/srv/acme/note.txt`, but her colleagues can | Mode bits (owner class) | `ls -l /srv/acme/note.txt`; `id alice` | `chmod u+r` as Alice or root. Do not add more `o+r`; the file is already open to others. |
| D | `cat /srv/acme/budget.txt` works for everybody, but `sudo labcat /srv/acme/budget.txt` is refused, even for root | MAC (AppArmor) | `sudo labcat /srv/acme/budget.txt`; `sudo journalctl -k \| grep -i 'apparmor.*DENIED'` | Add `/srv/acme/budget.txt r,` to the labcat profile and reload. Do not disable AppArmor or chmod the file. |
| E | bob can `cat /srv/acme/dropbox/hello.txt`, but `ls /srv/acme/dropbox` fails | Path (directory) | `namei -l /srv/acme/dropbox/hello.txt`; `ls -ld /srv/acme/dropbox` | If listing is intended, add `r` on the directory for bob's group or with an ACL. Do not remove `x` or chmod 777. If listing is not intended, leave it. |

### Q18. Two cases in more detail

(a) No, it is not a bug. Linux applies only the first matching class. Alice is the owner, so only `user::` is checked, and it is `---`. The group and other bits are not added to the owner's rights. `chmod u+r` fixes it.

(b) `x` on the directory lets you open a file when you already know its name. `r` lets you list the names. A dropbox or a mail spool uses this: users can read their own known file but cannot enumerate the directory. `/var/mail` is a common example.

### Q19. Debugging checklist

| Layer | What to check | Tool | Where I saw it |
|---|---|---|---|
| Path | Can I even reach the file? | `namei -l` | Q2, Q17 A and E |
| Mode bits | Which class applies to me, and what does it allow? | `ls -l`, `id` | Q2, Q4, Q17 C |
| ACL and mask | Is a named entry cut down by the mask? | `getfacl` | Q7, Q8, Q9, Q17 B |
| Role (sudo) | Is this exact command allowed for my role? | `sudo -l -U USER` | Q11 |
| MAC | Does the profile of the program allow this path? | `journalctl -k` | Q13, Q14, Q17 D |

### Q20. Before the CTF

(a) DAC and MAC still apply, but to the program's credentials: the kernel checks the file mode and ACLs against the program's effective UID and GID, and AppArmor checks the program's profile. The sudo role does not apply once the program is running.

(b) The rule limits the command and its arguments. It does not limit what the program can do internally: if the binary can read other files, spawn a shell or use a pager, those actions are still possible. The program's code and any MAC profile are the real limits.

(c) MAC. A root process is not stopped by DAC or by a sudo rule, but an AppArmor or SELinux profile can deny the open even for root.

(d) MAC is the last line. It does not protect against a compromised program that the profile allows, a kernel bug, a misconfigured profile, or data that leaves through an allowed path. It also does not fix a bad DAC policy; it only adds a second check.
