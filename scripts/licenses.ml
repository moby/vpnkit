(* Lookup package licenses and obligations, specifically Copyright statements since
   the source code is already freely available. *)

type license = {
  link: string;
  text: string;
}

let isc = {|
Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
|}

let mit = {|
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
|}

let bsd_2_clause_simplified = {|
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
|}

let bsd_3_clause_new_or_revised = {|
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
The name of the author may not be used to endorse or promote products derived from this software without specific prior written permission.
THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
|}

let lgpl21 = {|
GNU LESSER GENERAL PUBLIC LICENSE
Version 2.1, February 1999 


Copyright (C) 1991, 1999 Free Software Foundation, Inc.
59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
Everyone is permitted to copy and distribute verbatim copies
of this license document, but changing it is not allowed.

[This is the first released version of the Lesser GPL.  It also counts
 as the successor of the GNU Library Public License, version 2, hence
 the version number 2.1.]

Preamble
The licenses for most software are designed to take away your freedom to share and change it. By contrast, the GNU General Public Licenses are intended to guarantee your freedom to share and change free software--to make sure the software is free for all its users. 

This license, the Lesser General Public License, applies to some specially designated software packages--typically libraries--of the Free Software Foundation and other authors who decide to use it. You can use it too, but we suggest you first think carefully about whether this license or the ordinary General Public License is the better strategy to use in any particular case, based on the explanations below. 

When we speak of free software, we are referring to freedom of use, not price. Our General Public Licenses are designed to make sure that you have the freedom to distribute copies of free software (and charge for this service if you wish); that you receive source code or can get it if you want it; that you can change the software and use pieces of it in new free programs; and that you are informed that you can do these things. 

To protect your rights, we need to make restrictions that forbid distributors to deny you these rights or to ask you to surrender these rights. These restrictions translate to certain responsibilities for you if you distribute copies of the library or if you modify it. 

For example, if you distribute copies of the library, whether gratis or for a fee, you must give the recipients all the rights that we gave you. You must make sure that they, too, receive or can get the source code. If you link other code with the library, you must provide complete object files to the recipients, so that they can relink them with the library after making changes to the library and recompiling it. And you must show them these terms so they know their rights. 

We protect your rights with a two-step method: (1) we copyright the library, and (2) we offer you this license, which gives you legal permission to copy, distribute and/or modify the library. 

To protect each distributor, we want to make it very clear that there is no warranty for the free library. Also, if the library is modified by someone else and passed on, the recipients should know that what they have is not the original version, so that the original author's reputation will not be affected by problems that might be introduced by others. 

Finally, software patents pose a constant threat to the existence of any free program. We wish to make sure that a company cannot effectively restrict the users of a free program by obtaining a restrictive license from a patent holder. Therefore, we insist that any patent license obtained for a version of the library must be consistent with the full freedom of use specified in this license. 

Most GNU software, including some libraries, is covered by the ordinary GNU General Public License. This license, the GNU Lesser General Public License, applies to certain designated libraries, and is quite different from the ordinary General Public License. We use this license for certain libraries in order to permit linking those libraries into non-free programs. 

When a program is linked with a library, whether statically or using a shared library, the combination of the two is legally speaking a combined work, a derivative of the original library. The ordinary General Public License therefore permits such linking only if the entire combination fits its criteria of freedom. The Lesser General Public License permits more lax criteria for linking other code with the library. 

We call this license the "Lesser" General Public License because it does Less to protect the user's freedom than the ordinary General Public License. It also provides other free software developers Less of an advantage over competing non-free programs. These disadvantages are the reason we use the ordinary General Public License for many libraries. However, the Lesser license provides advantages in certain special circumstances. 

For example, on rare occasions, there may be a special need to encourage the widest possible use of a certain library, so that it becomes a de-facto standard. To achieve this, non-free programs must be allowed to use the library. A more frequent case is that a free library does the same job as widely used non-free libraries. In this case, there is little to gain by limiting the free library to free software only, so we use the Lesser General Public License. 

In other cases, permission to use a particular library in non-free programs enables a greater number of people to use a large body of free software. For example, permission to use the GNU C Library in non-free programs enables many more people to use the whole GNU operating system, as well as its variant, the GNU/Linux operating system. 

Although the Lesser General Public License is Less protective of the users' freedom, it does ensure that the user of a program that is linked with the Library has the freedom and the wherewithal to run that program using a modified version of the Library. 

The precise terms and conditions for copying, distribution and modification follow. Pay close attention to the difference between a "work based on the library" and a "work that uses the library". The former contains code derived from the library, whereas the latter must be combined with the library in order to run. 


TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
0. This License Agreement applies to any software library or other program which contains a notice placed by the copyright holder or other authorized party saying it may be distributed under the terms of this Lesser General Public License (also called "this License"). Each licensee is addressed as "you". 

A "library" means a collection of software functions and/or data prepared so as to be conveniently linked with application programs (which use some of those functions and data) to form executables. 

The "Library", below, refers to any such software library or work which has been distributed under these terms. A "work based on the Library" means either the Library or any derivative work under copyright law: that is to say, a work containing the Library or a portion of it, either verbatim or with modifications and/or translated straightforwardly into another language. (Hereinafter, translation is included without limitation in the term "modification".) 

"Source code" for a work means the preferred form of the work for making modifications to it. For a library, complete source code means all the source code for all modules it contains, plus any associated interface definition files, plus the scripts used to control compilation and installation of the library. 

Activities other than copying, distribution and modification are not covered by this License; they are outside its scope. The act of running a program using the Library is not restricted, and output from such a program is covered only if its contents constitute a work based on the Library (independent of the use of the Library in a tool for writing it). Whether that is true depends on what the Library does and what the program that uses the Library does. 

1. You may copy and distribute verbatim copies of the Library's complete source code as you receive it, in any medium, provided that you conspicuously and appropriately publish on each copy an appropriate copyright notice and disclaimer of warranty; keep intact all the notices that refer to this License and to the absence of any warranty; and distribute a copy of this License along with the Library. 

You may charge a fee for the physical act of transferring a copy, and you may at your option offer warranty protection in exchange for a fee. 

2. You may modify your copy or copies of the Library or any portion of it, thus forming a work based on the Library, and copy and distribute such modifications or work under the terms of Section 1 above, provided that you also meet all of these conditions: 


a) The modified work must itself be a software library. 
b) You must cause the files modified to carry prominent notices stating that you changed the files and the date of any change. 
c) You must cause the whole of the work to be licensed at no charge to all third parties under the terms of this License. 
d) If a facility in the modified Library refers to a function or a table of data to be supplied by an application program that uses the facility, other than as an argument passed when the facility is invoked, then you must make a good faith effort to ensure that, in the event an application does not supply such function or table, the facility still operates, and performs whatever part of its purpose remains meaningful. 
(For example, a function in a library to compute square roots has a purpose that is entirely well-defined independent of the application. Therefore, Subsection 2d requires that any application-supplied function or table used by this function must be optional: if the application does not supply it, the square root function must still compute square roots.) 

These requirements apply to the modified work as a whole. If identifiable sections of that work are not derived from the Library, and can be reasonably considered independent and separate works in themselves, then this License, and its terms, do not apply to those sections when you distribute them as separate works. But when you distribute the same sections as part of a whole which is a work based on the Library, the distribution of the whole must be on the terms of this License, whose permissions for other licensees extend to the entire whole, and thus to each and every part regardless of who wrote it. 

Thus, it is not the intent of this section to claim rights or contest your rights to work written entirely by you; rather, the intent is to exercise the right to control the distribution of derivative or collective works based on the Library. 

In addition, mere aggregation of another work not based on the Library with the Library (or with a work based on the Library) on a volume of a storage or distribution medium does not bring the other work under the scope of this License. 

3. You may opt to apply the terms of the ordinary GNU General Public License instead of this License to a given copy of the Library. To do this, you must alter all the notices that refer to this License, so that they refer to the ordinary GNU General Public License, version 2, instead of to this License. (If a newer version than version 2 of the ordinary GNU General Public License has appeared, then you can specify that version instead if you wish.) Do not make any other change in these notices. 

Once this change is made in a given copy, it is irreversible for that copy, so the ordinary GNU General Public License applies to all subsequent copies and derivative works made from that copy. 

This option is useful when you wish to copy part of the code of the Library into a program that is not a library. 

4. You may copy and distribute the Library (or a portion or derivative of it, under Section 2) in object code or executable form under the terms of Sections 1 and 2 above provided that you accompany it with the complete corresponding machine-readable source code, which must be distributed under the terms of Sections 1 and 2 above on a medium customarily used for software interchange. 

If distribution of object code is made by offering access to copy from a designated place, then offering equivalent access to copy the source code from the same place satisfies the requirement to distribute the source code, even though third parties are not compelled to copy the source along with the object code. 

5. A program that contains no derivative of any portion of the Library, but is designed to work with the Library by being compiled or linked with it, is called a "work that uses the Library". Such a work, in isolation, is not a derivative work of the Library, and therefore falls outside the scope of this License. 

However, linking a "work that uses the Library" with the Library creates an executable that is a derivative of the Library (because it contains portions of the Library), rather than a "work that uses the library". The executable is therefore covered by this License. Section 6 states terms for distribution of such executables. 

When a "work that uses the Library" uses material from a header file that is part of the Library, the object code for the work may be a derivative work of the Library even though the source code is not. Whether this is true is especially significant if the work can be linked without the Library, or if the work is itself a library. The threshold for this to be true is not precisely defined by law. 

If such an object file uses only numerical parameters, data structure layouts and accessors, and small macros and small inline functions (ten lines or less in length), then the use of the object file is unrestricted, regardless of whether it is legally a derivative work. (Executables containing this object code plus portions of the Library will still fall under Section 6.) 

Otherwise, if the work is a derivative of the Library, you may distribute the object code for the work under the terms of Section 6. Any executables containing that work also fall under Section 6, whether or not they are linked directly with the Library itself. 

6. As an exception to the Sections above, you may also combine or link a "work that uses the Library" with the Library to produce a work containing portions of the Library, and distribute that work under terms of your choice, provided that the terms permit modification of the work for the customer's own use and reverse engineering for debugging such modifications. 

You must give prominent notice with each copy of the work that the Library is used in it and that the Library and its use are covered by this License. You must supply a copy of this License. If the work during execution displays copyright notices, you must include the copyright notice for the Library among them, as well as a reference directing the user to the copy of this License. Also, you must do one of these things: 


a) Accompany the work with the complete corresponding machine-readable source code for the Library including whatever changes were used in the work (which must be distributed under Sections 1 and 2 above); and, if the work is an executable linked with the Library, with the complete machine-readable "work that uses the Library", as object code and/or source code, so that the user can modify the Library and then relink to produce a modified executable containing the modified Library. (It is understood that the user who changes the contents of definitions files in the Library will not necessarily be able to recompile the application to use the modified definitions.) 
b) Use a suitable shared library mechanism for linking with the Library. A suitable mechanism is one that (1) uses at run time a copy of the library already present on the user's computer system, rather than copying library functions into the executable, and (2) will operate properly with a modified version of the library, if the user installs one, as long as the modified version is interface-compatible with the version that the work was made with. 
c) Accompany the work with a written offer, valid for at least three years, to give the same user the materials specified in Subsection 6a, above, for a charge no more than the cost of performing this distribution. 
d) If distribution of the work is made by offering access to copy from a designated place, offer equivalent access to copy the above specified materials from the same place. 
e) Verify that the user has already received a copy of these materials or that you have already sent this user a copy. 
For an executable, the required form of the "work that uses the Library" must include any data and utility programs needed for reproducing the executable from it. However, as a special exception, the materials to be distributed need not include anything that is normally distributed (in either source or binary form) with the major components (compiler, kernel, and so on) of the operating system on which the executable runs, unless that component itself accompanies the executable. 

It may happen that this requirement contradicts the license restrictions of other proprietary libraries that do not normally accompany the operating system. Such a contradiction means you cannot use both them and the Library together in an executable that you distribute. 

7. You may place library facilities that are a work based on the Library side-by-side in a single library together with other library facilities not covered by this License, and distribute such a combined library, provided that the separate distribution of the work based on the Library and of the other library facilities is otherwise permitted, and provided that you do these two things: 


a) Accompany the combined library with a copy of the same work based on the Library, uncombined with any other library facilities. This must be distributed under the terms of the Sections above. 
b) Give prominent notice with the combined library of the fact that part of it is a work based on the Library, and explaining where to find the accompanying uncombined form of the same work. 
8. You may not copy, modify, sublicense, link with, or distribute the Library except as expressly provided under this License. Any attempt otherwise to copy, modify, sublicense, link with, or distribute the Library is void, and will automatically terminate your rights under this License. However, parties who have received copies, or rights, from you under this License will not have their licenses terminated so long as such parties remain in full compliance. 

9. You are not required to accept this License, since you have not signed it. However, nothing else grants you permission to modify or distribute the Library or its derivative works. These actions are prohibited by law if you do not accept this License. Therefore, by modifying or distributing the Library (or any work based on the Library), you indicate your acceptance of this License to do so, and all its terms and conditions for copying, distributing or modifying the Library or works based on it. 

10. Each time you redistribute the Library (or any work based on the Library), the recipient automatically receives a license from the original licensor to copy, distribute, link with or modify the Library subject to these terms and conditions. You may not impose any further restrictions on the recipients' exercise of the rights granted herein. You are not responsible for enforcing compliance by third parties with this License. 

11. If, as a consequence of a court judgment or allegation of patent infringement or for any other reason (not limited to patent issues), conditions are imposed on you (whether by court order, agreement or otherwise) that contradict the conditions of this License, they do not excuse you from the conditions of this License. If you cannot distribute so as to satisfy simultaneously your obligations under this License and any other pertinent obligations, then as a consequence you may not distribute the Library at all. For example, if a patent license would not permit royalty-free redistribution of the Library by all those who receive copies directly or indirectly through you, then the only way you could satisfy both it and this License would be to refrain entirely from distribution of the Library. 

If any portion of this section is held invalid or unenforceable under any particular circumstance, the balance of the section is intended to apply, and the section as a whole is intended to apply in other circumstances. 

It is not the purpose of this section to induce you to infringe any patents or other property right claims or to contest validity of any such claims; this section has the sole purpose of protecting the integrity of the free software distribution system which is implemented by public license practices. Many people have made generous contributions to the wide range of software distributed through that system in reliance on consistent application of that system; it is up to the author/donor to decide if he or she is willing to distribute software through any other system and a licensee cannot impose that choice. 

This section is intended to make thoroughly clear what is believed to be a consequence of the rest of this License. 

12. If the distribution and/or use of the Library is restricted in certain countries either by patents or by copyrighted interfaces, the original copyright holder who places the Library under this License may add an explicit geographical distribution limitation excluding those countries, so that distribution is permitted only in or among countries not thus excluded. In such case, this License incorporates the limitation as if written in the body of this License. 

13. The Free Software Foundation may publish revised and/or new versions of the Lesser General Public License from time to time. Such new versions will be similar in spirit to the present version, but may differ in detail to address new problems or concerns. 

Each version is given a distinguishing version number. If the Library specifies a version number of this License which applies to it and "any later version", you have the option of following the terms and conditions either of that version or of any later version published by the Free Software Foundation. If the Library does not specify a license version number, you may choose any version ever published by the Free Software Foundation. 

14. If you wish to incorporate parts of the Library into other free programs whose distribution conditions are incompatible with these, write to the author to ask for permission. For software which is copyrighted by the Free Software Foundation, write to the Free Software Foundation; we sometimes make exceptions for this. Our decision will be guided by the two goals of preserving the free status of all derivatives of our free software and of promoting the sharing and reuse of software generally. 

NO WARRANTY 

15. BECAUSE THE LIBRARY IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY FOR THE LIBRARY, TO THE EXTENT PERMITTED BY APPLICABLE LAW. EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES PROVIDE THE LIBRARY "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE LIBRARY IS WITH YOU. SHOULD THE LIBRARY PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING, REPAIR OR CORRECTION. 

16. IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY MODIFY AND/OR REDISTRIBUTE THE LIBRARY AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES, INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OR INABILITY TO USE THE LIBRARY (INCLUDING BUT NOT LIMITED TO LOSS OF DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY YOU OR THIRD PARTIES OR A FAILURE OF THE LIBRARY TO OPERATE WITH ANY OTHER SOFTWARE), EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES. 


END OF TERMS AND CONDITIONS
How to Apply These Terms to Your New Libraries
If you develop a new library, and you want it to be of the greatest possible use to the public, we recommend making it free software that everyone can redistribute and change. You can do so by permitting redistribution under these terms (or, alternatively, under the terms of the ordinary General Public License). 

To apply these terms, attach the following notices to the library. It is safest to attach them to the start of each source file to most effectively convey the exclusion of warranty; and each file should have at least the "copyright" line and a pointer to where the full notice is found. 


one line to give the library's name and an idea of what it does.
Copyright (C) year  name of author

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

Also add information on how to contact you by electronic and paper mail. 

You should also get your employer (if you work as a programmer) or your school, if any, to sign a "copyright disclaimer" for the library, if necessary. Here is a sample; alter the names: 


Yoyodyne, Inc., hereby disclaims all copyright interest in
the library `Frob' (a library for tweaking knobs) written
by James Random Hacker.

signature of Ty Coon, 1 April 1990
Ty Coon, President of Vice

That's all there is to it! 
|}

let lgpl21_with_ocaml_linking_exception = {|
This repository is distributed under the terms of the GNU Lesser General
Public License version 2.1 (included below).

As a special exception to the GNU Lesser General Public License, you
may link, statically or dynamically, a "work that uses the Library"
with a publicly distributed version of the Library to produce an
executable file containing portions of the Library, and distribute
that executable file under terms of your choice, without any of the
additional requirements listed in clause 6 of the GNU Lesser General
Public License.  By "a publicly distributed version of the Library",
we mean either the unmodified Library as distributed, or a
modified version of the Library that is distributed under the
conditions defined in clause 3 of the GNU Library General Public
License.  This exception does not however invalidate any other reasons
why the executable file might be covered by the GNU Lesser General
Public License.

------------

|} ^ lgpl21

let apache2 copyright = {|

Apache License
Version 2.0, January 2004
https://www.apache.org/licenses/

TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

1. Definitions.

"License" shall mean the terms and conditions for use, reproduction,
and distribution as defined by Sections 1 through 9 of this document.

"Licensor" shall mean the copyright owner or entity authorized by
the copyright owner that is granting the License.

"Legal Entity" shall mean the union of the acting entity and all
other entities that control, are controlled by, or are under common
control with that entity. For the purposes of this definition,
"control" means (i) the power, direct or indirect, to cause the
direction or management of such entity, whether by contract or
otherwise, or (ii) ownership of fifty percent (50%) or more of the
outstanding shares, or (iii) beneficial ownership of such entity.

"You" (or "Your") shall mean an individual or Legal Entity
exercising permissions granted by this License.

"Source" form shall mean the preferred form for making modifications,
including but not limited to software source code, documentation
source, and configuration files.

"Object" form shall mean any form resulting from mechanical
transformation or translation of a Source form, including but
not limited to compiled object code, generated documentation,
and conversions to other media types.

"Work" shall mean the work of authorship, whether in Source or
Object form, made available under the License, as indicated by a
copyright notice that is included in or attached to the work
(an example is provided in the Appendix below).

"Derivative Works" shall mean any work, whether in Source or Object
form, that is based on (or derived from) the Work and for which the
editorial revisions, annotations, elaborations, or other modifications
represent, as a whole, an original work of authorship. For the purposes
of this License, Derivative Works shall not include works that remain
separable from, or merely link (or bind by name) to the interfaces of,
the Work and Derivative Works thereof.

"Contribution" shall mean any work of authorship, including
the original version of the Work and any modifications or additions
to that Work or Derivative Works thereof, that is intentionally
submitted to Licensor for inclusion in the Work by the copyright owner
or by an individual or Legal Entity authorized to submit on behalf of
the copyright owner. For the purposes of this definition, "submitted"
means any form of electronic, verbal, or written communication sent
to the Licensor or its representatives, including but not limited to
communication on electronic mailing lists, source code control systems,
and issue tracking systems that are managed by, or on behalf of, the
Licensor for the purpose of discussing and improving the Work, but
excluding communication that is conspicuously marked or otherwise
designated in writing by the copyright owner as "Not a Contribution."

"Contributor" shall mean Licensor and any individual or Legal Entity
on behalf of whom a Contribution has been received by Licensor and
subsequently incorporated within the Work.

2. Grant of Copyright License. Subject to the terms and conditions of
this License, each Contributor hereby grants to You a perpetual,
worldwide, non-exclusive, no-charge, royalty-free, irrevocable
copyright license to reproduce, prepare Derivative Works of,
publicly display, publicly perform, sublicense, and distribute the
Work and such Derivative Works in Source or Object form.

3. Grant of Patent License. Subject to the terms and conditions of
this License, each Contributor hereby grants to You a perpetual,
worldwide, non-exclusive, no-charge, royalty-free, irrevocable
(except as stated in this section) patent license to make, have made,
use, offer to sell, sell, import, and otherwise transfer the Work,
where such license applies only to those patent claims licensable
by such Contributor that are necessarily infringed by their
Contribution(s) alone or by combination of their Contribution(s)
with the Work to which such Contribution(s) was submitted. If You
institute patent litigation against any entity (including a
cross-claim or counterclaim in a lawsuit) alleging that the Work
or a Contribution incorporated within the Work constitutes direct
or contributory patent infringement, then any patent licenses
granted to You under this License for that Work shall terminate
as of the date such litigation is filed.

4. Redistribution. You may reproduce and distribute copies of the
Work or Derivative Works thereof in any medium, with or without
modifications, and in Source or Object form, provided that You
meet the following conditions:

(a) You must give any other recipients of the Work or
Derivative Works a copy of this License; and

(b) You must cause any modified files to carry prominent notices
stating that You changed the files; and

(c) You must retain, in the Source form of any Derivative Works
that You distribute, all copyright, patent, trademark, and
attribution notices from the Source form of the Work,
excluding those notices that do not pertain to any part of
the Derivative Works; and

(d) If the Work includes a "NOTICE" text file as part of its
distribution, then any Derivative Works that You distribute must
include a readable copy of the attribution notices contained
within such NOTICE file, excluding those notices that do not
pertain to any part of the Derivative Works, in at least one
of the following places: within a NOTICE text file distributed
as part of the Derivative Works; within the Source form or
documentation, if provided along with the Derivative Works; or,
within a display generated by the Derivative Works, if and
wherever such third-party notices normally appear. The contents
of the NOTICE file are for informational purposes only and
do not modify the License. You may add Your own attribution
notices within Derivative Works that You distribute, alongside
or as an addendum to the NOTICE text from the Work, provided
that such additional attribution notices cannot be construed
as modifying the License.

You may add Your own copyright statement to Your modifications and
may provide additional or different license terms and conditions
for use, reproduction, or distribution of Your modifications, or
for any such Derivative Works as a whole, provided Your use,
reproduction, and distribution of the Work otherwise complies with
the conditions stated in this License.

5. Submission of Contributions. Unless You explicitly state otherwise,
any Contribution intentionally submitted for inclusion in the Work
by You to the Licensor shall be under the terms and conditions of
this License, without any additional terms or conditions.
Notwithstanding the above, nothing herein shall supersede or modify
the terms of any separate license agreement you may have executed
with Licensor regarding such Contributions.

6. Trademarks. This License does not grant permission to use the trade
names, trademarks, service marks, or product names of the Licensor,
except as required for reasonable and customary use in describing the
origin of the Work and reproducing the content of the NOTICE file.

7. Disclaimer of Warranty. Unless required by applicable law or
agreed to in writing, Licensor provides the Work (and each
Contributor provides its Contributions) on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied, including, without limitation, any warranties or conditions
of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
PARTICULAR PURPOSE. You are solely responsible for determining the
appropriateness of using or redistributing the Work and assume any
risks associated with Your exercise of permissions under this License.

8. Limitation of Liability. In no event and under no legal theory,
whether in tort (including negligence), contract, or otherwise,
unless required by applicable law (such as deliberate and grossly
negligent acts) or agreed to in writing, shall any Contributor be
liable to You for damages, including any direct, indirect, special,
incidental, or consequential damages of any character arising as a
result of this License or out of the use or inability to use the
Work (including but not limited to damages for loss of goodwill,
work stoppage, computer failure or malfunction, or any and all
other commercial damages or losses), even if such Contributor
has been advised of the possibility of such damages.

9. Accepting Warranty or Additional Liability. While redistributing
the Work or Derivative Works thereof, You may choose to offer,
and charge a fee for, acceptance of support, warranty, indemnity,
or other liability obligations and/or rights consistent with this
License. However, in accepting such obligations, You may act only
on Your own behalf and on Your sole responsibility, not on behalf
of any other Contributor, and only if You agree to indemnify,
defend, and hold each Contributor harmless for any liability
incurred by, or claims asserted against, such Contributor by reason
of your accepting any such warranty or additional liability.

END OF TERMS AND CONDITIONS

|} ^ copyright ^ {|

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
|}

let licenses = function
  | "angstrom.0.15.0" -> {
    link = "https://github.com/inhabitedtype/angstrom/blob/21333c8629ade0b99732a7c34c9513096d7efa05/LICENSE";
    text = {|
  Copyright (c) 2016, Inhabited Type LLC

All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

3. Neither the name of the author nor the names of his contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE CONTRIBUTORS ``AS IS'' AND ANY EXPRESS
OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.|}
  }
  | "arp.3.0.0" -> {
    link = "https://github.com/mirage/arp/blob/7222488873ae6d54233480322cb2f92a8df312ba/LICENSE.md";
    text = {|
Copyright (c) 2016 Hannes Mehnert hannes@mehnert.org
Portions copyright to MirageOS team under ISC license:
src/arp_packet.ml mirage/arpv4.mli mirage/arpv4.ml
    |} ^ isc
  }
  | "asetmap.0.8.1" -> {
    link = "https://github.com/dbuenzli/asetmap/blob/a3b70cfd95c6db04a1618db0bb3e8b77dbf164a9/LICENSE.md";
    text = {|
    Copyright (c) 2016 Daniel C. Bünzli
    |} ^ isc
  }
  | "astring.0.8.5" -> {
    link = "https://github.com/dbuenzli/astring/blob/ec7a266a3a680e5d246689855c639da53d713428/LICENSE.md";
    text = {|
    Copyright (c) 2016 The astring programmers
    |} ^ isc
  }
  | "fpath.0.7.3" -> {
    link = "https://raw.githubusercontent.com/dbuenzli/fpath/master/LICENSE.md";
    text = {|
    Copyright (c) 2014 The fpath programmers
    |} ^ isc
  }
  | "octavius.1.2.2" -> {
    link = "https://raw.githubusercontent.com/ocaml-doc/octavius/master/LICENSE.md";
    text = {|
    Copyright (c) 2015 Leo White <leo@lpw25.net>
    |} ^ isc
  }
  | "luv_unix.0.5.0" | "luv.0.5.11" -> {
    link = "https://raw.githubusercontent.com/aantron/luv/master/LICENSE.md";
    text = {|
    Copyright (c) 2018-2021 Anton Bachin
    |} ^ mit
  }
  | "integers.0.7.0" -> {
    link = "https://raw.githubusercontent.com/ocamllabs/ocaml-integers/0.7.0/LICENSE.md";
    text = {|
    Copyright (c) 2013-2016 Jeremy Yallop
    |} ^ mit
  }
  | "ctypes.0.20.1" -> {
    link = "https://raw.githubusercontent.com/ocamllabs/ocaml-ctypes/master/LICENSE";
    text = {|
    Copyright (c) 2013 Jeremy Yallop
    |} ^ mit
  }
  | "time_now.v0.14.0"
  | "stdio.v0.14.0"
  | "ppx_optcomp.v0.14.3"
  | "ppx_js_style.v0.14.1"
  | "ppx_inline_test.v0.14.1"
  | "ppx_here.v0.14.0"
  | "ppx_hash.v0.14.0"
  | "ppx_enumerate.v0.14.0"
  | "ppx_compare.v0.14.0"
  | "ppx_cold.v0.14.0"
  | "ppx_base.v0.14.0"
  | "ppx_assert.v0.14.0"
  | "jst-config.v0.14.1"
  | "jane-street-headers.v0.14.0"
  | "base.v0.14.2" | "base.v0.14.3"
  | "csexp.1.5.1"
  | "dune.2.9.1" | "dune.2.9.2" | "dune.2.9.3" | "dune.3.0.2" | "dune.3.0.3" | "dune.3.1.1" | "dune.3.2.0" | "dune.3.3.0" | "dune.3.4.1" | "dune.3.5.0"
  | "dune-configurator.2.9.1" | "dune-configurator.2.9.3" | "dune-configurator.3.0.2" | "dune-configurator.3.0.3" | "dune-configurator.3.1.1" | "dune-configurator.3.3.0" | "dune-configurator.3.5.0"
  | "dune-configurator.3.2.0" | "dune-configurator.3.4.1"
  | "ocaml-compiler-libs.v0.12.4"
  | "ocaml-syntax-shims.1.0.0"
  | "parsexp.v0.14.2"
  | "result.1.5"
  | "sexplib.v0.14.0"
  | "sexplib0.v0.14.0" -> {
    link = "https://github.com/janestreet/base/blob/83a70d184c98fb192d2030df1c3defea499195af/LICENSE.md";
    text = {|
    The MIT License

Copyright (c) 2016--2020 Jane Street Group, LLC opensource@janestreet.com
    |} ^ mit
  }
  | "base64.3.5.0" -> {
    link = "https://github.com/mirage/ocaml-base64/blob/3a5e259895acef979a0fab8bb59d396e1bccead0/LICENSE.md";
    text = {|
    Copyright (c) 2006-2009 Citrix Systems Inc.
    Copyright (c) 2010 Thomas Gazagnaire thomas@gazagnaire.com
    |} ^ isc
  }
  | "bigarray-compat.1.0.0" | "bigarray-compat.1.1.0" -> {
    link = "https://github.com/mirage/bigarray-compat/blob/757e11302b40619322fb839a8ef0cb0e16ba0828/LICENSE.md";
    text = {|
    Copyright (c) 2019-2021 Lucas Pluvinage lucas.pluvinage@gmail.com

    |} ^ isc
  }
  | "bigstringaf.0.8.0" | "bigstringaf.0.9.0" -> {
    link = "https://github.com/inhabitedtype/bigstringaf/blob/9c1e57375f3da15cf344c228e2cc14a36513923d/LICENSE";
    text = {|
    Copyright (c) 2018, Inhabited Type LLC

All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

3. Neither the name of the author nor the names of his contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE CONTRIBUTORS ``AS IS'' AND ANY EXPRESS
OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
    |}
  }
  | "cmdliner.1.0.4" | "cmdliner.1.1.1" -> {
    link = "https://github.com/dbuenzli/cmdliner/blob/93ee8854625a312d9ce69f83398bbc1e8443402f/LICENSE.md";
    text = {|
    Copyright (c) 2011 Daniel C. Bünzli
    |} ^ isc
  }
  | "cohttp.5.0.0" | "cohttp-lwt.5.0.0" -> {
    link = "https://github.com/mirage/ocaml-cohttp/blob/5f9c0ae88a69e4280810fe73344367e90954dea5/LICENSE.md";
    text = {|
    ISC License
Copyright (c) 2009-2018 <the authors, see individual headers on files>
    |} ^isc
  }
  | "cstruct.6.0.1" | "cstruct-lwt.6.0.1" | "cstruct-sexp.6.0.1" | "ppx_cstruct.6.0.1"
  | "cstruct.6.1.0" | "cstruct-lwt.6.1.0" | "cstruct-sexp.6.1.0" | "ppx_cstruct.6.1.0"
  | "cstruct.6.1.1" | "cstruct-lwt.6.1.1" | "cstruct-sexp.6.1.1" | "ppx_cstruct.6.1.1" -> {
    link = "https://raw.githubusercontent.com/mirage/ocaml-cstruct/v6.1.0/LICENSE.md";
    text = {|
    Copyright (c) 2012 Anil Madhavapeddy anil@recoil.org Copyright (c) 2012 Pierre Chambart Copyright (c) Christiano F. Haesbaert haesbaert@haesbaert.org Copyright (c) Citrix Inc Copyright (c) David Sheets sheets@alum.mit.edu Copyright (c) Drup drupyog@zoho.com Copyright (c) Hannes Mehnert hannes@mehnert.org Copyright (c) Jeremy Yallop yallop@gmail.com Copyright (c) Mindy Preston meetup@yomimono.org Copyright (c) Nicolas Ojeda Bar n.oje.bar@gmail.com Copyright (c) Richard Mortier mort@cantab.net Copyright (c) Rudi Grinberg rudi.grinberg@gmail.com Copyright (c) Thomas Gazagnaire thomas@gazagnaire.com Copyright (c) Thomas Leonard talex5@gmail.com Copyright (c) Vincent Bernardoff vb@luminar.eu.org Copyright (c) pqwy david@numm.org

    |}^isc
  }
  | "ethernet.3.0.0" -> {
    link = "https://github.com/mirage/ethernet/blob/6c93d92d0363165729a4d1f51c63b43bc4987c3c/LICENSE.md";
    text = {|
    Copyright (c) Anil Madhavapeddy anil@recoil.org Copyright (c) Balraj Singh balrajsingh@ieee.org Copyright (c) Citrix Inc Copyright (c) David Scott dave@recoil.org Copyright (c) Docker Inc Copyright (c) Drup drupyog@zoho.com Copyright (c) Gabor Pali pali.gabor@gmail.com Copyright (c) Hannes Mehnert hannes@mehnert.org Copyright (c) Haris Rotsos cr409@cam.ac.uk Copyright (c) Kia sadieperkins@riseup.net Copyright (c) Luke Dunstan LukeDunstan81@gmail.com Copyright (c) Magnus Skjegstad magnus@skjegstad.com Copyright (c) Mindy Preston meetup@yomimono.org Copyright (c) Nicolas Ojeda Bar n.oje.bar@gmail.com Copyright (c) Pablo Polvorin ppolvorin@process-one.net Copyright (c) Richard Mortier mort@cantab.net Copyright (c) Thomas Gazagnaire thomas@gazagnaire.org Copyright (c) Thomas Leonard talex5@gmail.com Copyright (c) Tim Cuthbertson tim@gfxmonk.net Copyright (c) Vincent Bernardoff vb@luminar.eu.org Copyright (c) lnmx len@lnmx.org Copyright (c) pqwy david@numm.org
    
    |} ^ isc
  }
  | "ezjsonm.1.3.0" -> {
    link = "https://github.com/mirage/ezjsonm/blob/a2b724b3bb084ce5045aca6f3431bf1abb096b6f/LICENSE";
    text = {|
    Copyright (c) 2013 Thomas Gazagnaire <thomas@gazagnaire.org>

    |} ^ isc
  }
  | "functoria-runtime.3.0.3" | "functoria-runtime.3.1.2" -> {
    link = "https://github.com/mirage/functoria/blob/d89fadb14bef0b1eb43761cdced0816e7772a533/LICENSE.md";
    text = {|
    Copyright (c) 2015-2018, Thomas Gazagnaire, Anil Madhavapeddy, Dave Scott, Thomas Leonard, Gabriel Radanne

    |} ^ isc
  }
  | "hex.1.4.0" | "hex.1.5.0" -> {
    link = "https://github.com/mirage/ocaml-hex/blob/a248fd213bd2248f610e8c5a7eeb39c92283896e/LICENSE.md";
    text = {|
    Copyright (c) 2015 Trevor Summers Smith trevorsummerssmith@gmail.com
    Copyright (c) 2014 Thomas Gazagnaire thomas@gazagnaire.org

    |} ^ isc
  }
  | "hvsock.3.0.0" -> {
    link = "https://github.com/mirage/ocaml-hvsock/blob/f4f4ff02b90f2c12568140b30fb8fceeedd8e2f1/LICENSE.md";
    text = {|
    Copyright (c) 2016, Dave Scott

    |} ^ isc
  }
  | "io-page.2.3.0" | "io-page-unix.2.3.0" -> {
    link = "https://github.com/mirage/io-page/blob/3e5b66ffbe922550c9b8b4c9c48b616efec65e61/LICENSE.md";
    text = {|
    Copyright (c) 2013 Thomas Gazagnaire thomas@gazagnaire.org Copyright (C) 2012-2013 Citrix Inc Copyright (c) 2010-2012 Anil Madhavapeddy anil@recoil.org
    |} ^ isc
  }
  | "ipaddr.5.2.0" | "ipaddr.5.3.0" | "ipaddr.5.3.1" | "ipaddr-sexp.5.2.0" | "ipaddr-sexp.5.3.0" | "ipaddr-sexp.5.3.1" | "macaddr.5.2.0" | "macaddr.5.3.0" | "macaddr.5.3.1" | "macaddr-cstruct.5.2.0" | "macaddr-cstruct.5.3.0" | "macaddr-cstruct.5.3.1" | "macaddr-sexp.5.2.0" | "macaddr-sexp.5.3.0" | "macaddr-sexp.5.3.1" -> {
    link = "https://github.com/mirage/ocaml-ipaddr/blob/7745ea4be2c1c5a7ab95908b26a6ed81a0947ab5/LICENSE.md";
    text = {|
    Copyright (c) 2013-2015 David Sheets sheets@alum.mit.edu Copyright (c) 2010-2011, 2014 Anil Madhavapeddy anil@recoil.org

    |} ^ isc
  }
  | "metrics.0.3.0" | "metrics.0.4.0" -> {
    link = "https://github.com/mirage/metrics/blob/0f48d63c5e1c0e33d7043b2c6e053ba380516433/LICENSE.md";
    text = isc;
  }
  | "mirage-channel.4.0.1" | "mirage-channel.4.1.0" -> {
    link = "https://raw.githubusercontent.com/mirage/mirage-channel/v4.1.0/LICENSE.md";
    text = {|
    Copyright (c) 2011-2015 Anil Madhavapeddy anil@recoil.org
    Copyright (c) 2015 Mindy Preston
    Copyright (c) 2015 Thomas Gazagnaire thomas@gazagnaire.org
    |} ^ isc
  }
  | "mirage-clock.4.0.0" | "mirage-clock-unix.4.0.0" | "mirage-clock.4.1.0" | "mirage-clock-unix.4.1.0" | "mirage-clock.4.2.0" | "mirage-clock-unix.4.2.0" -> {
    link = "https://github.com/mirage/mirage-clock/blob/5c1fa5e5818d1a5d8600894e95f07d48ad705c6f/LICENSE.md";
    text = {|
    Copyright (c) 2010 Anil Madhavapeddy anil@recoil.org 2014 Daniel C. Bünzli

    |} ^ isc
  }
  | "mirage-flow.3.0.0" | "mirage-flow-combinators.3.0.0" -> {
    link = "https://github.com/mirage/mirage-flow/blob/f5f6c131a9e72ac473719eb8740058385638a524/LICENSE.md";
    text = isc;
  }
  | "mirage-net.4.0.0" -> {
    link = "https://github.com/mirage/mirage-net/blob/f440f203ed2d1653f11d6c0b184dbbdfb94ef723/LICENSE.md";
    text = isc;
  }
  | "mirage-profile.0.9.1" -> {
    link = "https://github.com/mirage/mirage-profile/blob/5b6e0c3a6c2fe622eb081b0cc61c5c8637ab71d6/LICENSE.md";
    text = {|
    Copyright (c) 2014, Thomas Leonard All rights reserved.
    |} ^ bsd_2_clause_simplified;
  }
  | "mirage-random.3.0.0" -> {
    link = "https://github.com/mirage/mirage-random/blob/2f2434c30cedb476b44b10c55cec0052f1eaa1f4/LICENSE.md";
    text = isc;
  }
  | "mirage-random-stdlib.0.1.0" -> {
    link = "https://github.com/mirage/mirage-random-stdlib/blob/ee19066dbfa6f541d34261bdba65415bf1552b28/LICENSE.md";
    text = isc;
  }
  | "mirage-runtime.3.10.8" -> {
    link = "https://github.com/mirage/mirage/blob/main/LICENSE.md";
    text = {|
    Copyright (X) 2011-2018, the MirageOS contributors
    |} ^ isc
  }
  | "mirage-time.3.0.0" -> {
    link = "https://github.com/mirage/mirage-time/blob/c68f199b1952f0656526a3212f82afd2a49c1f00/LICENSE.md";
    text = isc;
  }
  | "mirage-vnetif.0.5.0" | "mirage-vnetif.0.6.0" -> {
    link = "https://github.com/mirage/mirage-vnetif/blob/8582e89c194b1253550daa755b4a4ff608bd07ca/LICENSE.md";
    text = {|
    Copyright (c) 2015, Magnus Skjegstad magnus@skjegstad.com

    |} ^ isc
  }
  | "mirage-stack.4.0.0" -> {
    link = "https://github.com/mirage/mirage-stack/blob/2d0fe8f5a198e04415eafd6496d5719f0a610e7e/LICENSE.md";
    text = isc;
  }
  | "pcap-format.0.5.2" | "pcap-format.0.6.0" -> {
    link = "https://github.com/mirage/ocaml-pcap/blob/76bf3ce75fed04a0625fc2a1c83545c0437bf823/LICENSE.md";
    text = {|
    Copyright (c) 2012-2018 The ocaml-pcap contributors

    |} ^ isc
  }
  | "prometheus.1.1" -> {
    link = "https://github.com/mirage/prometheus/blob/4a85699fa5e37975484fc99bdf3ff944a315a1ed/LICENSE.md";
    text = apache2 "Copyright 2016-2017 Docker, Inc."
  }
  | "protocol-9p.2.0.2" | "protocol-9p-unix.2.0.2" -> {
    link = "https://github.com/mirage/ocaml-9p/blob/931c745e45d685f4351f14ce50d2ca128895316f/LICENSE.md";
    text = {|
    Copyright (c) 2015, MirageOS
    |} ^ isc
  }
  | "uri.4.2.0" | "uri-sexp.4.2.0" -> {
    link = "https://github.com/mirage/ocaml-uri/blob/0ff3efbbc235bef5a7d67cc01bc1dadbe2e859b9/LICENSE.md";
    text = {|
    Copyright (c) <the authors, see individual headers on files>

    |} ^ isc
  }
  | "mirage-entropy.0.4.1" | "mirage-entropy.0.5.0" | "mirage-entropy.0.5.1" -> {
    link = "https://github.com/mirage/mirage-entropy/blob/8d4c9ed42dbea225b306af082acd8e15464287ba/LICENSE.md";
    text = {|
    Copyright (c) 2014-2016, Hannes Mehnert, Anil Madhavapeddy, David Kaloper Meršinjak
All rights reserved.

    |} ^ bsd_2_clause_simplified
  }
  | "mirage-kv.4.0.0" | "mirage-kv.4.0.1" | "mirage-kv.5.0.0" -> {
    link = "https://github.com/mirage/mirage-kv/blob/5c2c75e5a0efc0c9390b11fab75b1e706ea8d4ab/LICENSE.md";
    text = isc
  }
  | "mirage-protocols.8.0.0" -> {
    link = "https://github.com/mirage/mirage-protocols/blob/37aa4a86f9f423bb7fe1d70c8a71331060a45048/LICENSE.md";
    text = isc;
  }
  | "psq.0.2.0" | "psq.0.2.1" -> {
    link = "https://github.com/pqwy/psq/blob/beeaf9396655d195f9a20243102c9773d826d3b0/LICENSE.md";
    text = {|
    Copyright (c) 2016 David Kaloper Meršinjak

    |} ^ isc
  }
  | "randomconv.0.1.3" -> {
    link = "https://github.com/hannesm/randomconv/blob/045d7fd3454151930cb9941b0cd3a228ddebe68b/LICENSE.md";
    text = {|
    Copyright (c) 2016 Hannes Mehnert hannes@mehnert.org

    |} ^ isc
  }
  | "re.1.10.3" | "re.1.10.4" -> {
    link = "https://github.com/ocaml/ocaml-re/blob/c5d5df80e128c3d7646b7d8b1322012c5fcc35f3/LICENSE.md";
    text = {|
    This Software is distributed under the terms of the GNU Lesser
General Public License version 2.1 (included below), or (at your
option) any later version.

As a special exception to the GNU Library General Public License, you
may link, statically or dynamically, a "work that uses the Library"
with a publicly distributed version of the Library to produce an
executable file containing portions of the Library, and distribute
that executable file under terms of your choice, without any of the
additional requirements listed in clause 6 of the GNU Library General
Public License.  By "a publicly distributed version of the Library",
we mean either the unmodified Library, or a modified version of the
Library that is distributed under the conditions defined in clause 3
of the GNU Library General Public License.  This exception does not
however invalidate any other reasons why the executable file might be
covered by the GNU Library General Public License.

----------------------------------------------------------------------

    |} ^ lgpl21
  }
  | "mmap.1.1.0" | "mmap.1.2.0" -> {
    link = "https://github.com/mirage/mmap/blob/46f613db11c00667764523ccbb3d63e53e1c666c/LICENSE";
    text = {|
    In the following, "the OCaml Core System" refers to all files marked
"Copyright INRIA" in this distribution.

The OCaml Core System is distributed under the terms of the
GNU Lesser General Public License (LGPL) version 2.1 (included below).

As a special exception to the GNU Lesser General Public License, you
may link, statically or dynamically, a "work that uses the OCaml Core
System" with a publicly distributed version of the OCaml Core System
to produce an executable file containing portions of the OCaml Core
System, and distribute that executable file under terms of your
choice, without any of the additional requirements listed in clause 6
of the GNU Lesser General Public License.  By "a publicly distributed
version of the OCaml Core System", we mean either the unmodified OCaml
Core System as distributed by INRIA, or a modified version of the
OCaml Core System that is distributed under the conditions defined in
clause 2 of the GNU Lesser General Public License.  This exception
does not however invalidate any other reasons why the executable file
might be covered by the GNU Lesser General Public License.

----------------------------------------------------------------------

    |} ^ lgpl21
  }
  | "num.1.4" -> {
    link = "https://github.com/ocaml/num/blob/814c159ea6cebff3b1f61b2055b893be87084ae3/LICENSE";
    text = {|
    The Num library is copyright Institut National de Recherche en
Informatique et en Automatique (INRIA) and distributed under the terms of the
GNU Lesser General Public License (LGPL) version 2.1 (included below).

As a special exception to the GNU Lesser General Public License, you
may link, statically or dynamically, a "work that uses the Num
library" with a publicly distributed version of the Num library to
produce an executable file containing portions of the Num library, and
distribute that executable file under terms of your choice, without
any of the additional requirements listed in clause 6 of the GNU
Lesser General Public License.  By "a publicly distributed version of
the Num library", we mean either the unmodified Num library
available from https://github/com/ocaml/num, or a modified version of the Num
library that is distributed under the conditions defined in clause 2
of the GNU Lesser General Public License.  This exception does not
however invalidate any other reasons why the executable file might be
covered by the GNU Lesser General Public License.

The files in directory toplevel/ are taken from findlib and are covered by
the license in file toplevel/LICENSE-findlib.

----------------------------------------------------------------------

    |} ^ lgpl21
  }
  | "camlp-streams.5.0" | "camlp-streams.5.0.1" -> {
    link = "https://github.com/ocaml/camlp-streams/blob/trunk/LICENSE";
    text = {|
    The Camlp-streams library is copyright Institut National de Recherche
    en Informatique et en Automatique (INRIA) and distributed under the
    terms of the GNU Lesser General Public License (LGPL) version 2.1
    (included below).
  
    As a special exception to the GNU Lesser General Public License, you
    may link, statically or dynamically, a "work that uses the
    Camlp-streams library" with a publicly distributed version of the
    Camlp-streams library to produce an executable file containing
    portions of the Camlp-streams library, and distribute that executable
    file under terms of your choice, without any of the additional
    requirements listed in clause 6 of the GNU Lesser General Public
    License.  By "a publicly distributed version of the Camlp-streams
    library", we mean either the unmodified Camlp-streams library
    available from https://github/com/ocaml/camlp-streams, or a modified
    version of the Camlp-streams library that is distributed under the
    conditions defined in clause 2 of the GNU Lesser General Public
    License.  This exception does not however invalidate any other reasons
    why the executable file might be covered by the GNU Lesser General
    Public License.
    
    ----------------------------------------------------------------------
  
    |} ^ lgpl21
  }
  | "ocaml.4.08.0" | "ocaml-base-compiler.4.08.0"
  | "ocaml.4.12.0" | "ocaml-base-compiler.4.12.0"
  | "ocaml.4.13.0" | "ocaml-base-compiler.4.13.0"
  | "ocaml.4.13.1" | "ocaml-base-compiler.4.13.1"
  | "ocaml.4.14.0" | "ocaml-base-compiler.4.14.0"
  | "ocaml-variants.4.08.0+mingw64c"
  | "ocaml-variants.4.13.1+mingw64c"
  | "seq.base" | "stdlib-shims.0.3.0" | "uchar.0.0.2" -> {
    link = "https://github.com/ocaml/ocaml/blob/a095535e5c02a95da4908a82d9f75a62609cc592/LICENSE";
    text = {|
    In the following, "the OCaml Core System" refers to all files marked
"Copyright INRIA" in this distribution.

The OCaml Core System is distributed under the terms of the
GNU Lesser General Public License (LGPL) version 2.1 (included below).

As a special exception to the GNU Lesser General Public License, you
may link, statically or dynamically, a "work that uses the OCaml Core
System" with a publicly distributed version of the OCaml Core System
to produce an executable file containing portions of the OCaml Core
System, and distribute that executable file under terms of your
choice, without any of the additional requirements listed in clause 6
of the GNU Lesser General Public License.  By "a publicly distributed
version of the OCaml Core System", we mean either the unmodified OCaml
Core System as distributed by INRIA, or a modified version of the
OCaml Core System that is distributed under the conditions defined in
clause 2 of the GNU Lesser General Public License.  This exception
does not however invalidate any other reasons why the executable file
might be covered by the GNU Lesser General Public License.

----------------------------------------------------------------------

    |} ^ lgpl21
  }
  | "domain-name.0.4.0" | "duration.0.2.0" | "duration.0.2.1" -> {
    link = "https://github.com/hannesm/domain-name/blob/e9833486ee40ef2c49c43dd72976022a627b4a34/LICENSE.md";
    text = {|
    Copyright (c) 2017 2018 Hannes Mehnert hannes@mehnert.org
    |} ^ isc
  }
  | "cppo.1.6.8" | "cppo.1.6.9" -> {
    link = "https://github.com/ocaml-community/cppo/blob/94b2d0f21fcda5473773518a12afbcff45a52990/LICENSE.md";
    text = {|
    Copyright (c) 2009-2011 Martin Jambon All rights reserved.

    |}^bsd_3_clause_new_or_revised
  }
  | "fd-send-recv.2.0.1" -> {
    link = "https://github.com/xapi-project/ocaml-fd-send-recv/blob/7c9b151a7cc54f11c45280177027d9d42473737c/LICENSE";
    text = lgpl21_with_ocaml_linking_exception;
  }
  | "fmt.0.9.0" -> {
    link = "https://github.com/dbuenzli/fmt/blob/11221dcfd08c9b21c2dc63378fd6ffe75333fb33/LICENSE.md";
    text = {|
    Copyright (c) 2016 The fmt programmers

    |} ^ isc
  }
  | "logs.0.7.0" -> {
    link = "https://github.com/dbuenzli/logs/blob/346f2cb5279a0dfee0e57fff109b8994982ce66f/LICENSE.md";
    text = {|
    Copyright (c) 2016 The logs programmers

    |} ^ isc
  }
  | "rresult.0.7.0" -> {
    link = "https://github.com/dbuenzli/rresult/blob/e94378d2b216632970dc41f8ca6c71611acbaf03/LICENSE.md";
    text = {|
    Copyright (c) 2014 The rresult programmers

    |} ^ isc
  }
  | "jsonm.1.0.1" -> {
    link = "https://github.com/dbuenzli/jsonm/blob/15ba785854b8b6e45958570d23238b603cd3f8d6/LICENSE.md";
    text = {|
    Copyright (c) 2012 Daniel C. Bünzli
    |} ^ isc
  }
  | "uuidm.0.9.7" -> {
    link = "https://github.com/dbuenzli/uuidm/blob/091571745bc207eaf9aec450e36ff885b0b631e9/LICENSE.md";
    text = {|
    Copyright (c) 2008 Daniel C. Bünzli
    |} ^ isc
  }
  | "uutf.1.0.2" | "uutf.1.0.3" -> {
    link = "https://github.com/dbuenzli/uutf/blob/d43c88c0673b0d30dc34960645d0f992d68b23a1/LICENSE.md";
    text = {|
    Copyright (c) 2016 Daniel C. Bünzli
    |} ^ isc
  }
  | "uwt.0.3.3" | "uwt.0.3.4~dev" -> {
    link = "https://github.com/fdopen/uwt/blob/44276aa6755b92eddc9ad58662a968afad243e8b/LICENSE.md";
    text = {|
    Copyright (c) 2015-2018, the Authors of uwt (dist/AUTHORS)

    |} ^ mit
  }
  | "lru.0.3.0" | "lru.0.3.1" -> {
    link = "https://github.com/pqwy/lru/blob/3a0b5f9effa86f6615501a648069b9a12c5096e5/LICENSE.md";
    text = {|
    Copyright (c) 2016 David Kaloper Meršinjak
    |} ^ isc
  }
  | "lwt.5.5.0" | "lwt.5.6.1" | "lwt-dllist.1.0.1" -> {
    link = "https://github.com/ocsigen/lwt/blob/bab52d9744cb2d5cd3cfe86cda65ba73752998ee/LICENSE.md";
    text = {|
    Copyright (c) 1999-2020, the Authors of Lwt (docs/AUTHORS)

    |} ^ mit
  }
  | "menhir.20211230" | "menhirLib.20211230" | "menhirSdk.20211230"
  | "menhir.20220210" | "menhirLib.20220210" | "menhirSdk.20220210" -> {
    link = "https://gitlab.inria.fr/fpottier/menhir/-/blob/20211230/LICENSE";
    text = {|

THE RUNTIME LIBRARY is distributed under the terms of the GNU Library General
Public License version 2 (included below).
    
    |} ^ lgpl21_with_ocaml_linking_exception
  }
  | "ocplib-endian.1.2" -> {
    link = "https://github.com/OCamlPro/ocplib-endian/blob/10292cd3ffa4d23d737e3f855ad04f22d3d95460/COPYING.txt";
    text = lgpl21_with_ocaml_linking_exception;
  }
  | "ounit.2.2.4" | "ounit.2.2.6" | "ounit2.2.2.4" | "ounit2.2.2.6" -> {
    link = "https://github.com/gildor478/ounit/blob/faf4936b17507406c7592186dcaa3f25c6fc138a/LICENSE.txt";
    text = {|
    Copyright (c) 2002, 2003 by Maas-Maarten Zeeman
Copyright (c) 2010 by OCamlCore SARL
Copyright (C) 2013 Sylvain Le Gall

The package OUnit is copyright by Maas-Maarten Zeeman and OCamlCore SARL.

Permission is hereby granted, free of charge, to any person obtaining
a copy of this document and the OUnit software ("the Software"), to
deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute,
sublicense, and/or sell copies of the Software, and to permit persons
to whom the Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

The Software is provided ``as is'', without warranty of any kind,
express or implied, including but not limited to the warranties of
merchantability, fitness for a particular purpose and noninfringement.
In no event shall Maas-Maarten Zeeman be liable for any claim, damages
or other liability, whether in an action of contract, tort or
otherwise, arising from, out of or in connection with the Software or
the use or other dealings in the software.
    |}
  }
  | "sha.1.15.1" | "sha.1.15.2" -> {
    link = "https://github.com/djs55/ocaml-sha/blob/af5c7b1c7d3b8f9492038b7b40ba9cad82fb4ee8/LICENSE.md";
    text = isc;
  }
  | "stringext.1.6.0" -> {
    link = "https://github.com/rgrinberg/stringext/blob/2bce0a6fe54e8f8782f7a3b2be44a5e1fb37a522/LICENSE.md";
    text = {|
    Copyright (c) 2017 Rudi Grinberg

    |} ^ mit
  }
  | "tar.2.0.0" | "tar.2.0.1" -> {
    link = "https://github.com/mirage/ocaml-tar/blob/4da72c48eb1ea1066052216cdcfa12c5931c6eec/LICENSE.md";
    text = {|
    Copyright (c) 2012-2018 The ocaml-tar contributors

    |} ^ isc
  }
  | "tcpip.7.0.1" | "tcpip.7.1.0" | "tcpip.7.1.1" | "tcpip.7.1.2" -> {
    link = "https://github.com/mirage/mirage-tcpip/blob/353f7b92a1a8747923ce6918426fd3f82aa27445/LICENSE.md";
    text = {|
    Copyright (c) Anil Madhavapeddy <anil@recoil.org>
Copyright (c) Balraj Singh <balrajsingh@ieee.org>
Copyright (c) Citrix Inc
Copyright (c) David Scott <dave@recoil.org>
Copyright (c) Docker Inc
Copyright (c) Drup <drupyog@zoho.com>
Copyright (c) Gabor Pali <pali.gabor@gmail.com>
Copyright (c) Hannes Mehnert <hannes@mehnert.org>
Copyright (c) Haris Rotsos <cr409@cam.ac.uk>
Copyright (c) Kia <sadieperkins@riseup.net>
Copyright (c) Luke Dunstan <LukeDunstan81@gmail.com>
Copyright (c) Magnus Skjegstad <magnus@skjegstad.com>
Copyright (c) Mindy Preston <meetup@yomimono.org>
Copyright (c) Nicolas Ojeda Bar <n.oje.bar@gmail.com>
Copyright (c) Pablo Polvorin <ppolvorin@process-one.net>
Copyright (c) Richard Mortier <mort@cantab.net>
Copyright (c) Thomas Gazagnaire <thomas@gazagnaire.org>
Copyright (c) Thomas Leonard <talex5@gmail.com>
Copyright (c) Tim Cuthbertson <tim@gfxmonk.net>
Copyright (c) Vincent Bernardoff <vb@luminar.eu.org>
Copyright (c) lnmx <len@lnmx.org>
Copyright (c) pqwy <david@numm.org> 
    |} ^ isc
  }
  | "charrua.1.5.0" | "charrua-client.1.5.0" | "charrua-server.1.5.0"-> {
    link = "https://github.com/mirage/charrua/blob/fb614f77b8f4cbd5f6409453a8f030b21d7e1a93/LICENSE.md";
    text = {|
    Copyright (c) 2015-2017 Christiano F. Haesbaert <haesbaert@haesbaert.org>
Copyright (c) 2016 Gina Marie Maini <gina@beancode.io>
Copyright (c) 2016-2017 Mindy Preston

    |} ^ isc

  }
  | "vpnkit.0.2.0" -> {
    link = "https://github.com/moby/vpnkit/blob/master/LICENSE";
    text = apache2 "Copyright 2013-2016 Docker, Inc."
  }
  | "win-error.1.0" -> {
    link = "https://github.com/mirage/ocaml-win-error/blob/4cf370285d1d2e45cf750b037222cee0c6f52e9f/LICENSE";
    text = {|
    Copyright (c) 2016, Dave Scott

    |} ^ isc
  }
  | x -> failwith (Printf.sprintf "unknown license for " ^ x)

let linked_into_executable = function
  | "ocaml-config"
  | "conf-which" -> false (* part of OCaml infra *)
  | "ocamlbuild"
  | "ocamlfind"
  | "ppx_derivers"
  | "ppx_sexp_conv"
  | "ppx_tools"
  | "ppxlib" -> false
  | _ -> true

let base_package name = Stringext.chop_prefix ~prefix:"base-" name <> None

(* Command-line frontend and .csv parser: *)

let usage_msg = "licenses -in <deps.csv> -out <licenses.json>"
let output_file = ref "licenses.json"
let input_file = ref "deps.csv"

let speclist =
  [("-out", Arg.Set_string output_file, "Set output file name");
   ("-in", Arg.Set_string input_file, "Set input file name")]

let run cmd = match Unix.system cmd with
  | Unix.WEXITED 0 -> ()
  | Unix.WEXITED n -> failwith (Printf.sprintf "%s: %d" cmd n)
  | _ -> failwith (Printf.sprintf "%s: unexpected signal" cmd)

let trim_comment line = match Stringext.cut ~on:"#" line with
  | None -> line
  | Some (line, _comment) -> line

let () =
  Arg.parse speclist ignore usage_msg;
  let ic = open_in !input_file in
  let missing = ref [] in
  let parse_line line =
    let line = trim_comment line in
    if line = ""
    then None
    else match Stringext.split ~on:',' (trim_comment line) with
      | name :: package :: rest ->
        let name = String.trim name in
        let package = String.trim package in
        let license_ty = match rest with
          | [ x ] ->
            (* opam quotes these *)
            if String.length x >= 2 && x.[0] = '"' && x.[String.length x - 1] = '"'
            then String.sub x 1 (String.length x - 2)
            else x
          | _ -> "" in
        if linked_into_executable name && not(base_package name)
        then (try Some (package, license_ty, licenses package) with _ -> missing := package :: !missing; None)
        else None
      | _ ->
        failwith (Printf.sprintf "unable to parse %s" line) in
  let gather_licenses () =
    let all = ref [] in
    try
      while true do
        match parse_line (input_line ic) with
        | None -> ()
        | Some l -> all := l :: !all
      done;
      !all
    with
    | End_of_file -> !all in
  let all = gather_licenses () in
  if !missing <> [] then failwith (Printf.sprintf "unknown licenses for %s" (String.concat ", " !missing));
  let json = `A (List.map (fun (package, license_ty, license) ->
    `O [
      "name", `String package; (* name.version *)
      "type", `String license_ty;
      "link", `String license.link;
      "text", `String license.text;
    ]
    ) all) in
  let oc = open_out !output_file in
  Ezjsonm.to_channel ~minify:false oc json
