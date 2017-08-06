#pragma once

//classes used
#include <vector>
#include <Windows.h>
#include <stdio.h>
#include <map>
#include <set>
#include <vector>
#include <fstream>
#include <string>
#include <algorithm>
#include <random>
#include <time.h>

using namespace std;

class Signature {
public:
	int classID;
	int possible_class;
	int cluster;
	int signum;
	unsigned int ip_int;
	int window;
	int ttl;
	int df;
	//char options[20];
	unsigned long long options;
	int mss;
	int rst;
	int rst_ack;
	int rst_win;
	int rst_seq;
	int rst_broken;
	int syn_count;
	int rst_count;
	double prob;
	//vector<double> rto;
	vector<double> rto_cumulative;
	int lost_packets;
	Signature() { };
};

class ClassSignature {
public:
	int classID;
	int cluster;
	int window;
	int ttl;
	int df;
	unsigned long long options;
	int mss;
	int rst;
	int rst_ack;
	int rst_win;
	int rst_broken;
	int rto_size;
	vector<double> rep_rto;
	double distance_to_center;
	vector< pair<double, double> > min_max_rto; /*min and max for each rto*/
	vector< vector<double> > subOS_rto;
	vector<int> matched_positions;
	int lost_packets;
	double prob;
	ClassSignature() :rep_rto(21, 0) { };
};




