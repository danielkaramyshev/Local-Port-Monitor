import pyshark
import config
import os

def save_ip(ip):
    with open(config.save_file_path, "a") as myfile:
        myfile.write(ip + "\n")

def get_saved_ips():
    if not os.path.isfile(config.save_file_path):
        return []

    with open(config.save_file_path, "r") as myfile:
        saved_ips = myfile.read().splitlines()
    return saved_ips

def capture():
    saved_ips = get_saved_ips()
    capture = pyshark.LiveCapture(only_summaries=True, display_filter="(udp.dstport >= {0} and udp.dstport <= {1}) && (ip) && (udp)".format(config.port[0], config.port[1]))
    capture.sniff(timeout=5)

    for pkt in capture.sniff_continuously():
        packet = str(pkt).split()

        if packet[3] not in saved_ips:
            saved_ips.append(packet[3])
            print ("Just arrived:", (packet[3], packet[8]))
            save_ip(packet[3])


def main():
    capture()

if __name__ == "__main__":
    main()
