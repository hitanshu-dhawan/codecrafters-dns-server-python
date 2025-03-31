import socket
import argparse

from app.models import Header, Question, Answer


def parse_arguments():
    parser = argparse.ArgumentParser(description="A simple forwarding DNS server.")
    parser.add_argument("--resolver", type=str, help="DNS resolver in the form <ip>:<port>")
    return parser.parse_args()

def forward_query(resolver_address, resolver_port, query):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as resolver_socket:
        resolver_socket.sendto(query, (resolver_address, resolver_port))
        response, _ = resolver_socket.recvfrom(512)
    return response


def main():
    
    # Parse command line arguments
    args = parse_arguments()
    resolver_address, resolver_port = (args.resolver.split(":") if args.resolver else (None, None))
    if resolver_port:
        resolver_port = int(resolver_port)
    print(f"Resolver address: {resolver_address}, Resolver port: {resolver_port}")

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    
    while True:
        try:
            buf, source = udp_socket.recvfrom(512)

            # Log the received data
            print(f"Received data from {source}")
            print(f"Data: {buf.hex()}")
            print(f"Header received: {Header.decode(buf[:12])}")

            # Decode the DNS header
            # The header is the first 12 bytes of the DNS packet
            header = Header.decode(buf[:12])

            # Decode the questions
            # The question section starts after the header (12 bytes)
            questions = []
            offset = 12
            for i in range(header.qdcount):
                # Decode each question
                question, offset = Question.decode(buf, offset)
                questions.append(question)
                print(f"Question {i} received: {question}")

            answers = []
            for i, question in enumerate(questions):
                if resolver_address and resolver_port:
                    # Create a new header for the forwarded query
                    resolver_header = header
                    resolver_header.qdcount = 1 # Set the question count to 1
                    print(f"Forwarding query to {resolver_address}:{resolver_port}")
                    response = forward_query(resolver_address, resolver_port, resolver_header.encode() + question.encode()) # Forwarding only 1 question
                    print(f"Received response from resolver: {response.hex()}")

                    # Extract the answer from the response
                    offset_response = 12
                    try:
                        _, offset_response = Question.decode(response, offset_response)
                        answer, offset_response = Answer.decode(response, offset_response)
                    except Exception as e:
                        print(f"Failed to decode response: {e}")
                        answer = None
                answers.append(answer)
                print(f"Answer created: {answer}")

            # Set the header fields for the response
            header.qr = 1 # Set QR bit to 1 for response
            header.rcode = 0 if header.opcode == 0 else 4
            header.qdcount = len(questions) # Set the question count in the header
            header.ancount = len(answers) # Set the answer count in the header

            response = (
                header.encode() +
                b''.join([(question or '').encode() for question in questions]) +
                b''.join([(answer or '').encode() for answer in answers])
            )

            udp_socket.sendto(response, source)

        except Exception as e:
            print(f"Exception: {e}")
            break


if __name__ == "__main__":
    main()
