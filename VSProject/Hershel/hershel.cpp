/***
Hershel algorithm, Zain Shamsi Summer 2013
1. Calculate sample probability by
P(x|OSj) = P(x.rto|j.rto) P(x.constant|j.constant)
= sum (RTO prob for best combination for each subOS using laplace delay distribution * loss_prob_q^packets_lost)
+ each constant feature match * feature_prob_pi or no match * (1 - feature_prob_pi)
*/


#include "signature.h"

using namespace std;

class Shared_Vars {
public:
	HANDLE mutex;
	//storage of internet host rtos
	vector<Signature> samples_list;
	//storage of DB Signatures
	vector<ClassSignature> signature_list;

	int hosts_done, total_hosts;
	int cluster_success, class_success, fail, unclassified;
	int thread_id;

	vector<double> probs;
	map<int, double> classes;
	map<int, int> class_totals;
};

vector<Signature> createSigList(char *filename, bool first_field_ip);
map<int, string> readMapping(char* filename);
vector<ClassSignature> createClassList(vector<Signature>& sigs);
void OSMatchMaster(Shared_Vars* vars);
void OSMatchWorker(LPVOID thread_variables);
int options_match_int(unsigned long long tar_opts, unsigned long long sig_opts);
void calcProbs(Signature& target, vector<ClassSignature>& candidates);
int uniqueMatch(Signature& target, vector<ClassSignature>& candidates, double& highest_prob);

mt19937_64 mtgen;
uniform_real_distribution<double> uniform(0.0, 1.0);

#ifdef _DEBUG
int NUM_THREADS = 1;
#else
int NUM_THREADS = 6;
#endif

#define OPT_MSS 1 // max segment size
#define OPT_WIN 2 // window scaling
#define OPT_TS 3 // timestamps
#define OPT_SACK 4 // SACK allowed
#define OPT_EOL 5 // end of list (another type of padding?)
#define OPT_NOP 6 // padding

int RTO = 0;
int WIN = 0;
int TTL = 0;
int DF = 0;
int OPT = 0;
int MSS = 0;
int RST = 0;

#define JITTER_LAMBDA 2
#define JITTER_THRESHOLD 8
#define LOSS_PROB_Q 0.038
#define FEATURE_PROB_PI_RST_OPT 0.01
#define FEATURE_PROB_PI 0.1

#define REALDATA_RUN TRUE

bool SigCompare(Signature a, Signature b) {
	return (a.prob < b.prob);
}

class Estimator {
public:
	int y_nPkts;
	int x_nPkts;
	double subOS_prob;
	vector<double>& x_timestamps;
	vector<double>& y_timestamps;
	vector<double> accumulator;

	Estimator(vector<double>& sample, vector<double>& signature)
		:subOS_prob(0), x_timestamps(sample), y_timestamps(signature)
	{
		y_nPkts = signature.size();
		x_nPkts = sample.size();
		accumulator.resize(x_nPkts);
	}

	void ExamineCombination() {
		double temp_prob = 1;
		for (int i = 1; i < accumulator.size(); i++) {
			double g1 = x_timestamps[i] - x_timestamps[i - 1];
			double g2 = y_timestamps[accumulator[i]] - y_timestamps[accumulator[i - 1]];

			temp_prob *= exp(-JITTER_LAMBDA * abs(g1 - g2));
		}

		subOS_prob += temp_prob;
	}

	void ProduceLossPatterns(int remaining, int start, int accumulatorSize) {
		if (remaining > 0) {
			for (int i = start; i < y_nPkts - remaining + 1; i++) {
				bool possible = false;
				double diff = x_timestamps[accumulatorSize] - y_timestamps[i];
				if (diff >= 0) { // must arrive after the signature's timestamp		
					if (accumulatorSize == 0) // first packet being matched: allow it since the RTT can be anything
						possible = true;
					else {// non-first packet: do a test on jitter
						double jitt = x_timestamps[accumulatorSize] - x_timestamps[accumulatorSize - 1] -
							(y_timestamps[i] - y_timestamps[accumulator[accumulatorSize - 1]]);
						// TODO: automatically determine the value of jitter for this cutoff 
						// need the jitter PMF and some threshold: CDF sum above the threshold should be less than some small number
						if (abs(jitt) < JITTER_THRESHOLD) // only if less than "JITTER_THRESHOLD" OWD
							possible = true;
					}
				}
				if (possible) {
					accumulator[accumulatorSize] = i;
					ProduceLossPatterns(remaining - 1, i + 1, accumulatorSize + 1);
				}
			}
		}
		else {
			//if (produced == 0) // emulates always taking the first x[i].nPkts packets of the signature
			ExamineCombination();
			//produced ++;
		}
	}
};

int main(int argc, char* argv[]) {

	char* samples_filename = "internet_samples_test.txt";
	char* database_filename = "hershel_116DB.txt";
	char* mapping_filename = "class_to_os_mapping.txt";
	if (argc > 1) {
		if (argc < 5) {
			printf("Usage: %s num_threads database_file samples_file mapping_file\n", argv[0]);
			exit(0);
		}
		NUM_THREADS = atoi(argv[1]);
		database_filename = argv[2];
		samples_filename = argv[3];
		mapping_filename = argv[4];
	}

	printf("Running with\n\tDatabase file = %s\n\tSamples file = %s\n\tMapping file = %s\n\tNUM_THREADS = %d\n", database_filename, samples_filename, mapping_filename, NUM_THREADS);

	Shared_Vars sv;
	double start_time = clock();
	srand(time(NULL));

	//read signature data
	vector<Signature> file_signatures = createSigList(database_filename, false);
	sv.signature_list = createClassList(file_signatures);

	//read class mapping
	map<int, string> class_to_os_map = readMapping(mapping_filename);

	//read sample data
	sv.samples_list = createSigList(samples_filename, REALDATA_RUN); //CHANGE TO TRUE IF RUNNING REAL DATA
	if (!REALDATA_RUN) {
		//random_shuffle(sv.samples_list.begin(), sv.samples_list.end()); //randomly shuffle the samples to take out ordering bias
		//reverse(sv.signature_list.begin(), sv.signature_list.end());
		//random_shuffle(sv.signature_list.begin(), sv.signature_list.end());
	}


	//cluster signature data	
	//sv.clustered_list = runClustering(sv.signature_list);

	//run classification with selected features turned on	
	RTO = 1;
	WIN = 1;
	TTL = 1;
	DF = 1;
	OPT = 1;
	MSS = 1;
	RST = 1;

	OSMatchMaster(&sv);



	//Print results for internet scan
	if (REALDATA_RUN) {

		//sort result vector by probability
		sort(sv.samples_list.begin(), sv.samples_list.end(), SigCompare);

		int write_count = 0;
		FILE* fresult;

		fopen_s(&fresult, "summary_result.txt", "w");
		fprintf(fresult, "Class,Label,Count \n");
		for (auto x : sv.classes) fprintf(fresult, "%d, %s, %.0f\n", x.first, class_to_os_map[x.first].c_str(), x.second);
		fclose(fresult);

		fopen_s(&fresult, "probabilities.txt", "w");
		for (auto x : sv.samples_list) fprintf(fresult, "%0.16lf\n", x.prob);
		fclose(fresult);

		fopen_s(&fresult, "per_ip_result.txt", "w");

		fprintf(fresult, "IP,Class,Probability,||,Fingerprint Features,||,Signature Features\n");
		for (Signature f : sv.samples_list) {
			//print fingerprint
			fprintf(fresult, "%u,%d,%0.16lf,||,%d,%d,%d,%llu,%d,%d,%d,%d,%d", f.ip_int, f.possible_class, f.prob,
				f.window, f.ttl, f.df, f.options, f.rst, f.rst_ack, f.rst_win, f.rst_broken, f.mss);
			for (double r : f.rto_cumulative) fprintf(fresult, ",%lf", r);

			//print signature
			for (ClassSignature s : sv.signature_list) {
				if (s.classID == f.possible_class) {
					fprintf(fresult, ",||,%d,%d,%d,%llu,%d,%d,%d,%d,%d", s.window, s.ttl, s.df, s.options, s.rst, s.rst_ack, s.rst_win, s.rst_broken, s.mss);
					for (int i = 0; i < s.rto_size; i++)
						fprintf(fresult, ",%lf", s.rep_rto[i]);
				}
			}
			fprintf(fresult, "\n");

			write_count++;
			if (write_count % 1000000 == 0) printf("Written %d hosts\r", write_count);
		}

		fclose(fresult);
	}
	else {
		//for (auto m : sv.classes) printf("Class %d: Correct: %lf\n", m.first, m.second / sv.class_totals[m.first]);
	}

	double end_time = clock();
	double elapsed_time = ((end_time - start_time) / CLOCKS_PER_SEC) / 60;
	printf("elapsed time is %.2f minutes\n", elapsed_time);

	_fcloseall();
}

//read in signatures from file
vector<Signature> createSigList(char *filename, bool first_field_ip) {
	vector<Signature> ret_list;
	int sig_count = 0;
	int skip_count = 0;
	int BUFFER_SIZE = (1 << 26); //64MB

	FILE* fin;

	int ret = fopen_s(&fin, filename, "r");
	if (ret != 0) {
		printf("Error opening file %s!\n", filename);
		exit(0);
	}
	char* buffer = new char[BUFFER_SIZE];
	int count;
	double rto = 0;
	vector<double> rtos;

	while (!feof(fin)) {
		Signature sig;
		bool skip = false;

		//read next line
		fgets(buffer, BUFFER_SIZE, fin);
		char* bufferptr = buffer;

		if (first_field_ip)
			sscanf_s(bufferptr, "%u%*c%d%*c%d%*c%d%*c%d%*c%d%*c%d%*c%d%*c%d%*c%llu%*c%d%n",
				&sig.ip_int, &sig.window, &sig.ttl, &sig.df, &sig.rst, &sig.rst_ack, &sig.rst_win, &sig.rst_broken, &sig.mss, &sig.options, &sig.rst_count, &count);
		else
			sscanf_s(bufferptr, "%d%*c%d%*c%d%*c%d%*c%d%*c%d%*c%d%*c%d%*c%d%*c%d%*c%llu%n",
				&sig.classID, &sig.window, &sig.ttl, &sig.df, &sig.rst, &sig.rst_ack, &sig.rst_win, &sig.rst_seq, &sig.rst_broken, &sig.mss, &sig.options, &count);

		bufferptr += count;

		while (strcmp(bufferptr, "\n") != 0 && strlen(bufferptr) > 0) {
			sscanf_s(bufferptr, "%*c%lf%n", &rto, &count);
			sig.rto_cumulative.push_back(rto);

			//only care about signatures we can classify
			if (sig.rto_cumulative.size() > 21) { skip = true; break; }

			bufferptr += count;
		}
		
		if (!skip) {
			sig_count++;
			sig.signum = sig_count;

			ret_list.push_back(sig);
		}
		else skip_count++;

		if (sig_count % 1000000 == 0) printf("Read %d signatures, skipped %d...\r", sig_count, skip_count);
	}

	fclose(fin);
	printf("\nStored %d signatures in list\n", ret_list.size());
	printf("Skipped adding %d signatures\n", skip_count);
	return ret_list;
}

//read in mapping from file
map<int, string> readMapping(char *filename) {
	map<int, string> ret_map;
	int BUFFER_SIZE = (1 << 26); //64MB

	FILE* fin;

	int ret = fopen_s(&fin, filename, "r");
	if (ret != 0) {
		printf("Error opening file %s!\n", filename);
		exit(0);
	}
	char* buffer = new char[BUFFER_SIZE];

	int id;
	char os_name[500];

	while (!feof(fin)) {
		//read next line
		fgets(buffer, BUFFER_SIZE, fin);
		char* bufferptr = buffer;

		sscanf_s(bufferptr, "%d,%[^\n]", &id, os_name, _countof(os_name));				

		ret_map[id] = os_name;
	}

	fclose(fin);
	printf("\nStored %d mappings\n", ret_map.size());
	return ret_map;
}

//create representative signatures for each class (average of subOSes)
vector<ClassSignature> createClassList(vector<Signature>& sigs) {

	int current_sig = -1;
	vector<ClassSignature> clsigs;

	for (Signature s : sigs) {
		if (s.classID != current_sig) {
			//create new class Sig
			ClassSignature cs;
			cs.classID = s.classID;
			cs.window = s.window;
			cs.ttl = s.ttl;
			cs.df = s.df;
			cs.options = s.options;
			cs.mss = s.mss;
			cs.rst = s.rst;
			cs.rst_ack = s.rst_ack;
			cs.rst_win = s.rst_win;
			cs.rst_broken = s.rst_broken;
			cs.rto_size = s.rto_cumulative.size();
			cs.subOS_rto.push_back(s.rto_cumulative);
			for (double d : s.rto_cumulative) {
				cs.min_max_rto.push_back(pair<double, double>(d, d));
			}
			clsigs.push_back(cs);

			current_sig = s.classID;
		}
		else {
			for (int i = 0; i < s.rto_cumulative.size(); i++) {
				//update old classsig max/min
				if (s.rto_cumulative[i] < clsigs.back().min_max_rto[i].first) clsigs.back().min_max_rto[i].first = s.rto_cumulative[i];
				if (s.rto_cumulative[i] > clsigs.back().min_max_rto[i].second) clsigs.back().min_max_rto[i].second = s.rto_cumulative[i];
			}

			//push back this rto vector
			clsigs.back().subOS_rto.push_back(s.rto_cumulative);
		}
	}

	//create representative rto vector using midpoint of min/max
	/*for (int i = 0; i < clsigs.size(); i++){
	for (int j = 0; j < clsigs[i].min_max_rto.size(); j++){
	double mid = (clsigs[i].min_max_rto[j].second + clsigs[i].min_max_rto[j].first) / 2;
	clsigs[i].rep_rto[j] = mid;
	}
	}*/

	//create representative rto vector using average of 50 subOSes
	for (int i = 0; i < clsigs.size(); i++) {
		for (int s = 0; s < clsigs[i].subOS_rto.size(); s++) {
			for (int r = 0; r < clsigs[i].subOS_rto[s].size(); r++) {
				clsigs[i].rep_rto[r] = ((clsigs[i].rep_rto[r] * s) + clsigs[i].subOS_rto[s][r]) / (s + 1);
			}
		}
	}

	printf("Created %d representative vectors for each class\n", clsigs.size());

	return clsigs;
}

//set up variables and worker threads
void OSMatchMaster(Shared_Vars* vars) {
	//THREAD SETUP
	// thread handles are stored here; they can be used to check status of threads, or kill them
	HANDLE *handles = new HANDLE[NUM_THREADS];

	//set up counters
	vars->hosts_done = 0;
	vars->total_hosts = vars->samples_list.size();
	vars->class_success = 0;
	vars->cluster_success = 0;
	vars->fail = 0;
	vars->unclassified = 0;
	vars->thread_id = 0;
	// create a mutex for accessing critical sections; initial state = not locked
	vars->mutex = CreateMutex(NULL, 0, NULL);


	//Split Threads
	for (int i = 0; i < NUM_THREADS; i++) {
		handles[i] = CreateThread(NULL, 4096, (LPTHREAD_START_ROUTINE)OSMatchWorker, vars, 0, NULL);
		SetThreadPriority(handles[i], THREAD_PRIORITY_LOWEST);
	}

	//Print info every 5 secs until no more active threads
	printf("Started %d threads...\n\n", NUM_THREADS);
	bool loop = true;
	int sleep_interval = 5000;
	int ip_count, success_count, old_success_count = 0;
	double avg_rate = 0;
	double sum_rate = 0;
	int step = 0;
	int count_iter = 1;
	while (true) {
		WaitForSingleObject(vars->mutex, INFINITE); //LOCK Mutex to read shared vars

		success_count = vars->hosts_done;
		ip_count = vars->total_hosts - success_count;

		ReleaseMutex(vars->mutex); // RELEASE Mutex

		double rate = (success_count - old_success_count) / (double)(sleep_interval / 1000);

		sum_rate += rate;
		step++;
		avg_rate = sum_rate / step;
		double remaining = (ip_count / avg_rate) / 60;

		printf("IPs left: %d, Success: %d at %.2f per sec. %.2f min to go\r", ip_count, success_count, rate, remaining);

		old_success_count = success_count;
		if (ip_count <= 0) break;
		Sleep(sleep_interval);
	}

	//Wait for threads to return
	printf("\n--->Quit Condition Reached!<---\nWaiting for all threads to end..\n");
	WaitForMultipleObjects(NUM_THREADS, handles, TRUE, INFINITE);

	// Close handles
	for (int i = 0; i < NUM_THREADS; i++) CloseHandle(handles[i]);
	CloseHandle(vars->mutex);

	if (!REALDATA_RUN) {
		printf("\n------->CORRECT: %f, FAIL: %f, unclassified: %f\n",
			(double)vars->class_success / vars->total_hosts,
			(double)vars->fail / vars->total_hosts, (double)vars->unclassified / vars->total_hosts);
	}
	else printf("\nClassification Done. Quitting Master Thread\n");

}

//build candidate list for each host, 
void OSMatchWorker(LPVOID thread_variables) {
	Shared_Vars* vars = ((Shared_Vars*)thread_variables);
	Signature target;
	vector<ClassSignature> candidates;
	vector<ClassSignature> sig_list(vars->signature_list); //give each thread a copy of the siglist
	int total = vars->total_hosts;

	WaitForSingleObject(vars->mutex, INFINITE); //LOCK Mutex to read shared vars
												//get thread id
	int myid = vars->thread_id;
	vars->thread_id++;
	ReleaseMutex(vars->mutex); // RELEASE Mutex

	//run through all internet hosts and classify
	for (int i = myid; i < total; i += NUM_THREADS) {
		//get next host
		target = vars->samples_list[i];
		int classID;
		double highest_prob;


		if (RTO) {
			for (int sig_index = 0; sig_index < sig_list.size(); sig_index++) {				
				//get difference in lengths
				int diff;
				diff = sig_list[sig_index].rto_size - target.rto_cumulative.size();

				//apply loss filter
				if (diff >= 0) { 	
					candidates.push_back(sig_list[sig_index]);					
				}//close loss filter
			}//close loop


			//Class Matching
			//probability storage
			calcProbs(target, candidates);
			classID = uniqueMatch(target, candidates, highest_prob);
		}
		else {
			//if not using RTO, all signatures are candidates, so send whole sig_list
			candidates = sig_list;
			classID = uniqueMatch(target, candidates, highest_prob);
		}

		vars->samples_list[i].possible_class = classID;
		//vars->samples_list[i].prob = highest_prob;

		//not simply highest prob, but highest prob normalized over sum of all other candidates
		double sum = 0;
		for (ClassSignature can : candidates) sum += can.prob;
		if (sum > 0) vars->samples_list[i].prob = highest_prob / sum;
		else vars->samples_list[i].prob = 0;

		WaitForSingleObject(vars->mutex, INFINITE); //LOCK Mutex to read shared vars
													
		if (REALDATA_RUN) {
			vars->classes[classID]++;
			vars->probs.push_back(highest_prob);
		}
		else {
			if (classID == target.classID) {
				vars->class_success++;
				vars->classes[classID]++;
			}
			else {
				vars->fail++;
			}
			vars->class_totals[target.classID]++;
		}
		
		vars->hosts_done++;
		ReleaseMutex(vars->mutex); // RELEASE Mutex

		//clear candidate list
		candidates.clear();
	}

}

//stores in each candidate its probability calculated from jitter and LOSS_PROBABILITY (summation of subOS probs)
void calcProbs(Signature& target, vector<ClassSignature>& candidates) {
	double class_prob;

	//for each class
	for (int j = 0; j < candidates.size(); j++) {
		class_prob = 0;
		double subOS_prob = 0;

		int lost_packets = candidates[j].rto_size - target.rto_cumulative.size();

		if (lost_packets < 0) { printf("LOST PACKETS: %d\n", lost_packets); exit(0); }

		//for each subOS
		for (int r = 0; r < candidates[j].subOS_rto.size(); r++) {
			//for (int r = 0; r < 1; r++){ //this is for only checking one subOS / average

			//get the probability of this subOS rto vs. target using estimator
			Estimator e(target.rto_cumulative, candidates[j].subOS_rto[r]);
			//Estimator e(target.rto_cumulative, candidates[j].rep_rto); //this is for 50-subOS average only
			e.ProduceLossPatterns(target.rto_cumulative.size(), 0, 0);
			subOS_prob = e.subOS_prob;

			subOS_prob *= pow(LOSS_PROB_Q, lost_packets) * pow(1 - LOSS_PROB_Q, target.rto_cumulative.size());

			//if (subOS_prob > class_prob) class_prob = subOS_prob; //for highest subOS prob - about 10% less accuracy
			class_prob += subOS_prob; //for all subOS prob
		}

		candidates[j].prob = class_prob;
	}
}

//calculate likeliest class by adding FEATURE_CHANGE_PROBABILITY onto candidates
int uniqueMatch(Signature& target, vector<ClassSignature>& candidates, double& highest_prob) {
	highest_prob = 0;
	int best_class = -1;

	if (!RTO) {
		vector<int> winners; //store tied classes

		//if not using RTO, do a constant score match for simplicity and to avoid probability rounding errors
		for (int i = 0; i < candidates.size(); i++) {
			candidates[i].prob = 0;
			if (WIN) {
				if (target.window == candidates[i].window) candidates[i].prob++;
			}
			if (TTL) {
				if (target.ttl == candidates[i].ttl) candidates[i].prob++;
			}
			if (DF) {
				if (target.df == candidates[i].df) candidates[i].prob++;
			}
			if (MSS) {
				if (target.mss == candidates[i].mss) candidates[i].prob++;
			}
			if (target.rst) {
				if (RST) {
					if (target.rst == candidates[i].rst && target.rst_ack == candidates[i].rst_ack	&& target.rst_win == candidates[i].rst_win && target.rst_broken == candidates[i].rst_broken) candidates[i].prob++;
				}
			}
			if (OPT) {
				int oval = options_match_int(target.options, candidates[i].options);
				if (oval >= 1) candidates[i].prob++;
			}

			if (candidates[i].prob > highest_prob) {
				highest_prob = candidates[i].prob;
				winners.clear();
				winners.push_back(candidates[i].classID);
			}
			if (candidates[i].prob == highest_prob) {
				winners.push_back(candidates[i].classID);
			}
		}

		//return winners.back(); //return last class seen
		int random = rand() % winners.size(); //return one of tied winners randomly picked
		return winners[random];
	}

	for (int i = 0; i < candidates.size(); i++) {
		if (WIN) {
			if (target.window == candidates[i].window) candidates[i].prob *= (1 - FEATURE_PROB_PI);
			else candidates[i].prob *= FEATURE_PROB_PI;
		}
		if (TTL) {
			if (target.ttl == candidates[i].ttl) candidates[i].prob *= (1 - FEATURE_PROB_PI);
			else candidates[i].prob *= FEATURE_PROB_PI;
		}
		if (DF) {
			if (target.df == candidates[i].df) candidates[i].prob *= (1 - FEATURE_PROB_PI);
			else candidates[i].prob *= FEATURE_PROB_PI;
		}
		if (MSS) {
			if (target.mss == candidates[i].mss) candidates[i].prob *= (1 - FEATURE_PROB_PI);
			else candidates[i].prob *= FEATURE_PROB_PI;
		}
		if (target.rst) {
			if (RST) {
				if (target.rst == candidates[i].rst && target.rst_ack == candidates[i].rst_ack	&& target.rst_win == candidates[i].rst_win && target.rst_broken == candidates[i].rst_broken) candidates[i].prob *= (1 - FEATURE_PROB_PI_RST_OPT);
				else candidates[i].prob *= FEATURE_PROB_PI_RST_OPT;

			}
		}
		if (OPT) {
			int oval = options_match_int(target.options, candidates[i].options);
			if (oval == 0) candidates[i].prob *= FEATURE_PROB_PI_RST_OPT;
			else if (oval >= 1) candidates[i].prob *= (1 - FEATURE_PROB_PI_RST_OPT);
		}

		if (candidates[i].prob > highest_prob) {
			highest_prob = candidates[i].prob;
			best_class = candidates[i].classID;
		}
	}

	return best_class;
}

//match int64 options, intersection of both tar and sig should be ordered the same
int options_match_int(unsigned long long tar_opts, unsigned long long sig_opts) {
	if (tar_opts == sig_opts) return 2;

	int count = 0;

	//keep track of where we found our last option in sig list
	int last_found_position = -1;
	unsigned long long sig_it;

	while (tar_opts > 0) {
		int opt = -1;
		while (opt != OPT_MSS && opt != OPT_WIN && opt != OPT_SACK && opt != OPT_TS) { //skip unimportant bits
			if (tar_opts == 0) return 1; //we've matched so far and reached 0 without another option
										 //get last 3 bits from target
			opt = tar_opts & 0x7; //AND by 3 bits to get value
								  //move to next option
			tar_opts = tar_opts >> 3;
		}

		sig_it = sig_opts; //reset iterator to beginning
		int position = 0;
		bool found = false;
		while (sig_it > 0) { //go through sig_opt list
			int sopt = sig_it & 0x7;
			if (sopt == opt) { //if found
				if (position < last_found_position) return 0; //found it before the last one, doesnt match ordering
				else last_found_position = position;
				found = true;
				break;
			}
			sig_it = sig_it >> 3;
			position++;
		}
		if (!found) {
			//not found in list, was probably enabled by user - do nothing here
		}
	}

	//all there
	return 1;
}
