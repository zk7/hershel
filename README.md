This file and all files mentioned below are part of Hershel. 

Copyright © 2014-2015 IRL at Texas A&M University (http://irl.cse.tamu.edu)
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, 
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, 
this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, 
this list of conditions and the following disclaimer in the documentation 
and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its 
contributors may be used to endorse or promote products derived from this 
software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED 
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR 
PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS 
BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER 
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, 
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE 
USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

Contact:
	Dmitri Loguinov (dmitri@cse.tamu.edu)

Data, code, and signatures:
	http://irl.cse.tamu.edu/projects/sampling

Publication:
	Z. Shamsi, A. Nandwani, D. Leonard and D. Loguinov, "Hershel: 
	Single-Packet OS Fingeprinting," ACM SIGMETRICS, June 2014.

Files:

HershelDB_116OS.txt:  Contains OS signatures for 116 OSes in plain 
text format. It has the following format:
	int id
	int tcp_window
	int ip_ttl
	int ip_df
	string tcp_options
	longlong tcp_options_encoded
	int mss
	int rst_present
	int rst_ack flag
	int rst_window
	int rst_sequence
	int rst_nonzero
	double RTT (0 value)
	double RTO1_timestamp
	double RTO2_timestamp
	double RTO3_timestamp
	...

observations.txt: Sample observed signatures used in Hershel.cpp to classify using
Hershel

class-to-os-mapping.txt:  Maps plain text description of device to signature data 
in database
