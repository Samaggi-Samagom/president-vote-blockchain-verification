from os import listdir
from os.path import join
from cryptography.fernet import Fernet, InvalidToken
from cryptography.exceptions import InvalidSignature
from collections import Counter
import base64


INITIAL_DATA = "gAAAAABkjUtBL9vxTiHe_rZSBs6OJFVmMAQIlLWqb1GJAXG4-6S8CYImNfmk6nc3Bk3YuAp0RrT8R1ipa8ea_j3mV-G5z1P8UUQ7QzllO4lfyn9eN3w5l-ujiw5hmQxvX1njXLNgeoT6VroiSmOJvPn_3pLQ0TkaxVpyGqopkpL7nH04QfzLCfJj__zqNyXbD7SD2kfiI6ndRvYVhV8Kh8teEnbzVFFu-g=="


def begin():
    verification_files = listdir("./verification-data")
    verification_data = []

    for each_file in verification_files:
        with open(join("./verification-data", each_file), "r") as f:
            verification_data.append(f.read().split("$NL-CHR$")[:-1])

    previous_vote_data = INITIAL_DATA
    end = False

    sequenced_raw = []
    sequenced_data = []
    verified_votes = {}

    verifier_index_cache = []

    i = 0
    ttl = sum(len(x) for x in verification_data)

    while not end:
        if not any([len(f) > 0 for f in verification_data]):
            end = True
        for k, whole_data in enumerate(verification_data):
            if not whole_data:
                continue

            print(f"------ Decrypting Vote {i} of {ttl} ------\n")
            print(f"Trying: \n"
                  f"Data: {whole_data[0]}\n"
                  f"From: {verification_files[k]}\n"
                  f"Using: {previous_vote_data}")

            try:
                data = fernet_decrypt(whole_data[0], previous_vote_data)
            except (InvalidToken, InvalidSignature):
                print("FAILED")
                # if whole_data[0] == _list[-1]:
                #     raise FileNotFoundError("Failed to find match to decrypt.")
                # else:
                #     continue
                if k == len(verification_data) - 1:
                    # whole_data.pop(0)
                    raise FileNotFoundError("Failed to find match to decrypt.")
                continue
            except IndexError:
                break
            else:
                print("SUCCESS")
                i += 1
                verifier_index_cache.append(k)

                raw_data = whole_data.pop(0)
                sequenced_raw.append(raw_data)

                vote = data[:2]
                secure_id = data[2:]

                sequenced_data.append({"secure_id": secure_id, "vote_value": vote})

                if vote in verified_votes:
                    verified_votes[vote] += 1
                else:
                    verified_votes[vote] = 1

                previous_vote_data = raw_data

                break

    print("\n\n")
    print("####### REPORT #######")
    print(f"Initial Encryption Key: \"{INITIAL_DATA}\"")
    print(f"Number of Verifiers: {len(verification_data)}")
    print(f"Verifier Dispatch Bias:")
    [print(f"    - Verifier {v} Bias {b}") for v, b in calculate_bias(verifier_index_cache, verification_files)]
    print()
    print(f"####### VERIFIED VOTE COUNT #######")
    [print(f"{value} : {num_votes}") for value, num_votes in verified_votes.items()]
    print()
    print("####### RAW SEQUENCED VOTE DATA #######")
    [print(f"SEQ {i:04}: {x}") for i, x in enumerate(sequenced_raw)]
    print()
    print("####### SEQUENCED VOTE DATA #######")
    [print(f"SEQ {i:04}: {x}") for i, x in enumerate(sequenced_data)]



def calculate_bias(index_data, verifier_file_names):
    occurrences = Counter(index_data)
    average = sum(occurrences.values())/len(occurrences)
    normalised = [(verifier_file_names[k].replace(".txt", ""), x/average) for k, x in occurrences.items()]

    return normalised


def fernet_encrypt(data: str, key: str) -> str:
    encryptor = Fernet(create_key(key))

    return encryptor.encrypt(data.encode("utf-8")).decode("utf-8")


def fernet_decrypt(data: str, key: str) -> str:
    encryptor = Fernet(create_key(key))

    return encryptor.decrypt(data.encode("utf-8")).decode("utf-8")


def create_key(key: str):
    truncated_key = key[:32]
    filled_key = truncated_key + "ThisIsAFillerForTheKeyUsedInTheEncryption"[:32-len(key)]

    return base64.urlsafe_b64encode(filled_key.encode("utf-8"))


if __name__ == '__main__':
    begin()
