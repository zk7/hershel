//    Copyright © 2014 IRL at Texas A&M University (http://irl.cse.tamu.edu)
//
//    This file is part of Hershel.
//
//    Hershel is free software: you can redistribute it and/or modify
//    it under the terms of the GNU Lesser General Public License as published by
//    the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.
//
//    Hershel is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU Lesser General Public License for more details
//    http://www.gnu.org/licenses/lgpl.txt.
//
//    Contact:
//	  Dmitri Loguinov (dmitri@cse.tamu.edu)
//
//    Data and signatures:
//    http://irl.cse.tamu.edu/projects/sampling
//
//    Publication:
//	  Z. Shamsi, A. Nandwani, D. Leonard and D. Loguinov, "Hershel: 
//	  Single-Packet OS Fingerprinting" ACM SIGMETRICS, June 2014.
//

#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <vector>
#include <unordered_map>
#include <random>
#include <cstring>
#include <stdlib.h>

#define OPT_MSS 1 // max segment size
#define OPT_WIN 2 // window scaling
#define OPT_TS 3 // timestamps
#define OPT_SACK 4 // SACK allowed
#define OPT_EOL 5 // end of list (another type of padding?)
#define OPT_NOP 6 // padding

//parameters for Hershel matching
#define H_JITTER_LOSS_THRESHOLD 8 //how many seconds of jitter we can tolerate when figuring out loss combinations

#define H_JITTER_MEAN 0.5
#define H_JITTER_LAMBDA (1 / H_JITTER_MEAN)
#define H_LOSS_PROB 0.038
#define H_FEATURE_PROB_PI_RST_OPT 0.01
#define H_FEATURE_PROB_PI 0.1

#define Q_GUESS_LIMIT_IN_SECS 4.0
#define Q_NUM_BINS 100

using namespace std;

vector<double> jitter_prob_array;
class Signature{
public:
	unsigned int id_classified;
	unsigned int id;
	int win;
	int ttl;
	int df;
	int rst;
	int rst_ack;
	int rst_win;
	int rst_seq;
	int rst_nonzero;
	int mss;
	char options_str[25];
	unsigned long long options_int;
	vector<double> packet_arrival_time;
};

//Hershel RTO Estimator
class HershelEstimator{
public:
	int y_nPkts;
	int x_nPkts;
	double subOS_prob;
	vector<double>& x_timestamps;
	vector<double>& y_timestamps;
	vector<int> accumulator;

	HershelEstimator(vector<double>& sample, vector<double>& signature)
		:subOS_prob(0), x_timestamps(sample), y_timestamps(signature)
	{
		y_nPkts = signature.size();
		x_nPkts = sample.size();
		accumulator.resize(x_nPkts);
	}

	void ExamineCombination(){
		double temp_prob = 1;
		for (int i = 1; i < accumulator.size(); i++){
			double g1 = x_timestamps[i] - x_timestamps[i - 1];
			double g2 = y_timestamps[accumulator[i]] - y_timestamps[accumulator[i - 1]];

			//replace Laplace calculation with pregenerated PMF
			int jitter_index = abs(g1 - g2) / (Q_GUESS_LIMIT_IN_SECS / Q_NUM_BINS);
			if (jitter_index > jitter_prob_array.size() - 1) jitter_index = jitter_prob_array.size() - 1;
			temp_prob *= jitter_prob_array[jitter_index];

		}

		subOS_prob += temp_prob;
	}


	void ProduceLossPatterns(int remaining, int start, int accumulatorSize){
		if (remaining > 0){
			for (int i = start; i < y_nPkts - remaining + 1; i++){
				bool possible = false;
				//Optimization: Check if timestamp tau_i(m) > tau_j(m). Provides a good speedup
				double diff = x_timestamps[accumulatorSize] - y_timestamps[i];
				if (diff >= 0){ // must arrive after the signature's timestamp		
					if (accumulatorSize == 0) // first packet being matched: allow it since the RTT can be anything
						possible = true;
					else {// non-first packet: do a test on jitter
						double jitt = x_timestamps[accumulatorSize] - x_timestamps[accumulatorSize - 1] -
							(y_timestamps[i] - y_timestamps[accumulator[accumulatorSize - 1]]);
						if (abs(jitt) < H_JITTER_LOSS_THRESHOLD) // only if less than "JITTER_THRESHOLD" OWD
							possible = true;
					}
				}
				if (possible){
					accumulator[accumulatorSize] = i;
					ProduceLossPatterns(remaining - 1, i + 1, accumulatorSize + 1);
				}
			}
		}
		else {
			ExamineCombination();
		}
	}
};

//match int64 options, intersection of both target and sig should be ordered the same
int options_match_int(unsigned long long tar_opts, unsigned long long sig_opts){
	if (tar_opts == sig_opts) return 2;

	int count = 0;

	//keep track of where we found our last option in sig list
	int last_found_position = -1;
	unsigned long long sig_it;

	while (tar_opts > 0){
		int opt = -1;
		while (opt != OPT_MSS && opt != OPT_WIN && opt != OPT_SACK && opt != OPT_TS){ //skip unimportant bits
			if (tar_opts == 0) return 1; //we've matched so far and reached 0 without another option
			//get last 3 bits from target
			opt = tar_opts & 0x7; //AND by 3 bits to get value
			//move to next option
			tar_opts = tar_opts >> 3;
		}

		sig_it = sig_opts; //reset iterator to beginning
		int position = 0;
		bool found = false;
		while (sig_it > 0){ //go through sig_opt list
			int sopt = sig_it & 0x7;
			if (sopt == opt){ //if found
				if (position < last_found_position) return 0; //found it before the last one, doesnt match ordering
				else last_found_position = position;
				found = true;
				break;
			}
			sig_it = sig_it >> 3;
			position++;
		}
		if (!found){
			//not found in list, was probably enabled by user - keep going
		}
	}

	//all there
	return 1;
}

//calculate likeliest class by adding FEATURE_CHANGE_PROBABILITY onto candidates
double constantMatching(Signature& target, Signature& dbsig, double& prob){

	if (target.win == dbsig.win) prob *= (1 - H_FEATURE_PROB_PI);
	else prob *= H_FEATURE_PROB_PI;

	if (target.ttl == dbsig.ttl) prob *= (1 - H_FEATURE_PROB_PI);
	else prob *= H_FEATURE_PROB_PI;

	if (target.df == dbsig.df) prob *= (1 - H_FEATURE_PROB_PI);
	else prob *= H_FEATURE_PROB_PI;

	int oval = options_match_int(target.options_int, dbsig.options_int);
	if (oval <= 1) prob *= H_FEATURE_PROB_PI_RST_OPT;
	else if (oval > 1) prob *= (1 - H_FEATURE_PROB_PI_RST_OPT);

	if (target.mss == dbsig.mss) prob *= (1 - H_FEATURE_PROB_PI);
	else prob *= H_FEATURE_PROB_PI;

	if (target.rst){
		if (target.rst == dbsig.rst && target.rst_ack == dbsig.rst_ack	&& target.rst_win == dbsig.rst_win && target.rst_nonzero == dbsig.rst_nonzero) prob *= (1 - H_FEATURE_PROB_PI_RST_OPT);
		else prob *= H_FEATURE_PROB_PI_RST_OPT;
	}
	return prob;
}

void Hershel(unordered_map<unsigned int, vector<Signature>>& database, vector<Signature>& observations){
	printf("\n---Starting Hershel Classification---\n");

	//set up OWD probabilities
	double sum = 0;
	for (int s = 0; s < Q_NUM_BINS; s++) {
		double x = (s + 1) * Q_GUESS_LIMIT_IN_SECS / Q_NUM_BINS;
		double prob = exp(-H_JITTER_LAMBDA * x);
		jitter_prob_array.push_back(prob);
		sum += prob;
	}
	//normalize array
	for (int i = 0; i < jitter_prob_array.size(); i++){
		jitter_prob_array[i] = jitter_prob_array[i] / sum;
	}

	int unclassified = 0;
	int correct = 0;
	int fail = 0;

	//run through all observations and classify
	for (int i = 0; i < observations.size(); i++){
		//get next host
		Signature target = observations[i];
		double highest_prob = 0;
		unsigned int highest_id = 0;

		//for (int sig_index = 0; sig_index < vars->database_sigs.size(); sig_index++){
		for (auto it = database.begin(); it != database.end(); it++){
			double os_prob = 0;

			//get difference in lengths
			int lost_packets = it->second[0].packet_arrival_time.size() - target.packet_arrival_time.size();

			//apply loss filter, cant receive more packets than signature
			if (lost_packets >= 0){

				//for each subOS
				for (int r = 0; r < it->second.size(); r++){

					//get the probability of this subOS rto vs. target using estimator
					HershelEstimator e(target.packet_arrival_time, it->second[r].packet_arrival_time);
					e.ProduceLossPatterns(target.packet_arrival_time.size(), 0, 0);

					os_prob += e.subOS_prob; //for all subOS prob
				}

				//multiply by lost packet prob
				os_prob *= pow(H_LOSS_PROB, lost_packets) * pow(1 - H_LOSS_PROB, target.packet_arrival_time.size());

				//match constants			
				constantMatching(target, it->second[0], os_prob);
			}

			//track highest prob
			if (os_prob > highest_prob){
				highest_prob = os_prob;
				highest_id = it->first;
			}
		}

		if (highest_id == 0) unclassified++;
		observations[i].id_classified = highest_id;

	}

}

vector<Signature> readSigList(char *filename){
	//read signatures into vector
	vector<Signature> retvec;
	int sig_count = 0;
	int BUFFER_SIZE = (1 << 10); //1MB

	FILE* fin = fopen(filename, "r");
	if (fin == NULL){
		printf("Error opening file %s!\n", filename);
		exit(-1);
	}
	else printf("\nReading from %s...\n", filename);
	char* buffer = new char[BUFFER_SIZE];
	int count, count_discard = 0;
	double timestamp = 0;
	unsigned int old_ip = 0;
	vector<double> rtos;

	while (!feof(fin)){
		Signature sig;

		//read next line
		fgets(buffer, BUFFER_SIZE, fin);
		char* bufferptr = buffer;

		sscanf(bufferptr, "%u,%d,%d,%d,%[^,],%lld,%d,%d,%d,%d,%d,%d%n",
			&sig.id, &sig.win, &sig.ttl, &sig.df, sig.options_str, &sig.options_int, &sig.mss, &sig.rst, &sig.rst_ack, &sig.rst_win, &sig.rst_seq, &sig.rst_nonzero, &count);

		bufferptr += count;

		while (strcmp(bufferptr, "\n") != 0 && strlen(bufferptr) > 0){
			sscanf(bufferptr, ",%lf%n", &timestamp, &count);
			sig.packet_arrival_time.push_back(timestamp);

			bufferptr += count;
		}

		retvec.push_back(sig);
		sig_count++;
		if (sig_count % 10000 == 0) printf("Read %d signatures...\r", sig_count);
	}

	fclose(fin);
	printf("Stored %d signatures in map\n", retvec.size());
	return retvec;
}

int main(int argc, char* argv[]){
	if (argc < 4){
		printf("To run: %s database_file observations_file os_mapping_file\n", argv[0]);
		return 0;
	}

	//read database signatures
	vector<Signature> database_sigs = readSigList(argv[1]);
	//combine them into a hashmap for easier organization
	unordered_map<unsigned int, vector<Signature>> database;
	for (Signature s : database_sigs) database[s.id].push_back(s);

	//read observations
	vector<Signature> observations = readSigList(argv[2]);

	//read class to OS mapping
	FILE *fin = fopen(argv[3], "r");
	unordered_map<int, string> os_mapping;
	char buffer[512];
	while (!feof(fin)){
		int id;
		char osname[512];

		fgets(buffer, 512, fin);
		sscanf(buffer, "%d,%[^\n]", &id, osname);
		os_mapping[id] = string(osname);
	}
	
	//run Hershel on observations
	Hershel(database, observations);

	//print out observation results
	for (Signature o : observations) printf("Observation %d classified as id %d (%s)\n", o.id, o.id_classified, os_mapping[o.id_classified].c_str());
}
