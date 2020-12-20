# Contribution

## Code Contributions

To make a contribution, follow these steps.

1. Create a change description in the format specified below to
    use in the source control commit log.
2. Your commit message must include your ``Signed-off-by`` signature
3. It is preferred that contributions are submitted using the same
   copyright license as the base project. When that is not possible,
    then contributions using the following licenses can be accepted:

-  BSD (2-clause): http://opensource.org/licenses/BSD-2-Clause
-  BSD (3-clause): http://opensource.org/licenses/BSD-3-Clause
-  MIT: http://opensource.org/licenses/MIT

For documentation:

-  FreeBSD Documentation License
    https://www.freebsd.org/copyright/freebsd-doc-license.html

Contributions of code put into the public domain can also be accepted.

Contributions using other licenses might be accepted, but further
review will be required.

## Developer Certificate of Origin

Your change description should use the standard format for a
commit message, and must include your ``Signed-off-by`` signature.

In order to keep track of who did what, all patches contributed must
include a statement that to the best of the contributor's knowledge
they have the right to contribute it under the specified license.

The test for this is as specified in the `Developer's Certificate of
Origin (DCO) 1.1 <https://developercertificate.org/>`__. The contributor
certifies compliance by adding a line saying

Signed-off-by: Developer Name developer@example.org

where ``Developer Name`` is the contributor's real name, and the email
address is one the developer is reachable through at the time of
contributing.

   <pre>
    Developer's Certificate of Origin 1.1

    By making a contribution to this project, I certify that:

    (a) The contribution was created in whole or in part by me and I
        have the right to submit it under the open source license
        indicated in the file; or

    (b) The contribution is based upon previous work that, to the best
        of my knowledge, is covered under an appropriate open source
        license and I have the right under that license to submit that
        work with modifications, whether created in whole or in part
        by me, under the same open source license (unless I am
        permitted to submit under a different license), as indicated
        in the file; or

    (c) The contribution was provided directly to me by some other
        person who certified (a), (b) or (c) and I have not modified
        it.

    (d) I understand and agree that this project and the contribution
        are public and that a record of the contribution (including all
        personal information I submit with it, including my sign-off) is
        maintained indefinitely and may be redistributed consistent with
        this project or the open source license(s) involved.
   </pre>

## Sample Change Description / Commit Message

   <pre>
    From: Contributor Name <contributor@example.com>
    Subject: Brief-single-line-summary

    Full-commit-message

    Signed-off-by: Contributor Name <contributor@example.com>
   </pre>

## GIT configuration and usage

Please use below configuration for ~/.gitconfig

   <pre>
   [user]
       name = Your Name
       email = your.name@domain.com
   [format]
       coverLetter = auto
   [sendemail]
       smtpserver = smtp.domain.com
       confirm = always
       suppresscc = self
   [core]
       autocrlf = false
   </pre>

Please always rebase your patch to the latest master. Please use "rebase and merge" instead of "merge commit".

Please test your patch with "git am --3way --ignore-space-change --keep-cr *.patch" to master.

## Test before patch submission

1) Please build with Visual Studio 2019 in Windows and GCC in Linux, at least IA32 and X64 version.

2) Please run OsTest (SpdmResponderEmu.exe / SpdmRequesterEmu.exe) and UnitTest (TestSpdmResponder.exe / TestSpdmRequester.exe) to ensure they can still pass.

## Patch submission

Please create a [pull-request](https://github.com/jyao1/openspdm/pulls) if it is possible.

Alternatively, you may also submit git patch directly to jiewen.yao@intel.com for review.