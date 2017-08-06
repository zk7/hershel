# Hershel

Hershel is an OS fingerprinting algorithm that determines the OS of a remote host using a single outbound TCP SYN packet. It uses several features from the IP/TCP headers and adds TCP retransmission timeouts (RTOs) as its standout feature. Our paper builds the stochastic theory required to handle Internet queueing delays and packet loss that may occur when observing TCP RTOs. We then use Hershel to accomplish fingerprinting on an Internet-wide port-80 scan.

In addition to adding new features, Hershel also allows standard header fields (e.g., TCP Window size, IP TTL, IP DF etc.) to exhibit volatility, i.e., a probability that a user changes these features. Results from experiments in the journal publication show that Hershel can still retain accuracy even against popular fingerprint scrubbers.

# Publication
### Conference
Z. Shamsi, A. Nandwani, D. Leonard and D. Loguinov, "Hershel: Single-Packet OS Fingeprinting," ACM SIGMETRICS, June 2014.

	@inproceedings{shamsi2014,
		title={Hershel: Single-Packet OS Fingerprinting},
		author={Zain Shamsi and Ankur Nandwani and Derek Leonard and Dmitri Loguinov},
		booktitle={ACM SIGMETRICS},
		year={2014},
		organization={ACM}
		location = {Austin, Texas, USA},
		pages = {195--206},
		doi = {10.1145/2591971.2591972},
		keywords = {internet measurement, os classification, device fingerprinting},
 	} 

[ACM Portal](http://dl.acm.org/citation.cfm?id=2591972) 

[Direct Paper Link](http://irl.cs.tamu.edu/people/zain/papers/sigmetrics2014.pdf)

### Journal
Z. Shamsi, A. Nandwani, D. Leonard, and D. Loguinov, "Hershel: Single-Packet OS Fingerprinting,"  IEEE/ACM Transactions on Networking, vol. 24, no. 4, August 2016.
	
	@ARTICLE{shamsi2016, 
		author={Zain Shamsi and Ankur Nandwani and Derek Leonard and Dmitri Loguinov}, 
		journal={IEEE/ACM Transactions on Networking}, 
		title={Hershel: Single-Packet OS Fingerprinting}, 
		year={2016}, 
		month={Aug},
		volume={24}, 
		number={4}, 
		pages={2196-2209}, 
		doi={10.1109/TNET.2015.2447492}, 
		ISSN={1063-6692}, 	
	}

[IEEE Xplore](http://ieeexplore.ieee.org/document/7150435/) 

[Direct Paper Link](http://irl.cs.tamu.edu/people/zain/papers/ton2016.pdf)

# Files

Hershel is written in C++.

The project contains two versions of the algorithm: a multi-platform single-threaded version which should compile on most systems. It includes the Hershel 116 OS database and some test signatures.

The Visual Studio project files use the Windows library for multi-threading and hence compiles in Win32/64. It also includes the Hershel database and example signatures. This is likely the version you want to run if you have a large dataset.

### File structure

The data files containing the OS and Internet signatures have mostly the same text format. For the files in the multi-platform folder, this is format:

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
	double RTT (0 value for database)
	double RTO1_timestamp
	double RTO2_timestamp
	double RTO3_timestamp
	...

HershelDB.txt contains the database signatures, observations.txt contains sample observed signatures that are classified using the Hershel algorithm. The class-to-os-mapping.txt maps plain text label of the device to signature data in database.


