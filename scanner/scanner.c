#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>

#define MAX_THREADS 256
#define MAX_PORTS 1024

struct thread_data {
	int thread_id;
	struct in_addr ip;
	int ports[MAX_PORTS];
	int num_ports;
};

void *scan_ports(void *threadarg) {
	struct thread_data *data;
	int sockfd, port;
	struct sockaddr_in target;

	data = (struct thread_data *) threadarg;
	// 扫描此IP的所有端口
	for (int i = 0; i < data->num_ports; i++) {
		port = data->ports[i];
		sockfd = socket(AF_INET, SOCK_STREAM, 0);

		target.sin_family = AF_INET;
		target.sin_addr = data->ip;
		target.sin_port = htons(port);
		// 连接此IP的此端口, 如果连接成功, 则说明此端口开放, 进行输出
		if (connect(sockfd, (struct sockaddr *)&target, sizeof(target)) == 0) {
			printf("Host %s:%d is open\n", inet_ntoa(data->ip), port);
		}

		close(sockfd);
	}

	pthread_exit(NULL);
}

int main() {
	struct ifaddrs *ifaddr, *ifa;
	struct sockaddr_in *sa;
	int family, s;
	char host[NI_MAXHOST];

	// 获取系统中所有网络接口的信息
	if (getifaddrs(&ifaddr) == -1) {
		perror("getifaddrs");
		exit(EXIT_FAILURE);
	}

	int num_threads = 0;
	pthread_t threads[MAX_THREADS];
	struct thread_data thread_data_array[MAX_THREADS];

	// 遍历这些接口以获取其IP地址
	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL) {
			continue;
		}

		family = ifa->ifa_addr->sa_family;

		if (family == AF_INET) {
			// 获取接口的IP地址
			s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);

			if (s != 0) {
				printf("getnameinfo() failed: %s\n", gai_strerror(s));
				exit(EXIT_FAILURE);
			}

			printf("Scanning ports for interface %s (%s):\n", ifa->ifa_name, host);

			// 创建线程扫描此IP的端口
			struct thread_data data;
			data.thread_id = num_threads++;
			inet_aton(host, &data.ip);

			// 扫描此IP端口 1-65535
			data.num_ports = 65535;
			for (int i = 0; i < data.num_ports; i++) {
				data.ports[i] = i + 1;
			}

			thread_data_array[data.thread_id] = data;
			// 创建多线程, 进入scan_ports函数进行扫描
			if (pthread_create(&threads[data.thread_id], NULL, scan_ports, (void *)&thread_data_array[data.thread_id])) {
				printf("Error creating thread for interface %s\n", ifa->ifa_name);
				exit(EXIT_FAILURE);
			}
		}
	}

	freeifaddrs(ifaddr);

	for (int i = 0; i < num_threads; i++) {
		pthread_join(threads[i], NULL);
	}
	// 完成扫描
	printf("Done scanning ports for all interfaces.\n");

	return 0;
}
