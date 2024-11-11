from crypt import *
import math
import random as rnd
import numpy as np
import requests
from collections import Counter

def cut_string_into_pairs(text):
  pairs = []
  for i in range(0, len(text) - 1, 2):
    pairs.append(text[i:i + 2])
  if len(text) % 2 != 0:
    pairs.append(text[-1] + '_')  # Add a placeholder if the string has an odd number of characters
  return pairs

def load_text_from_web(url):
  try:
    response = requests.get(url)
    response.raise_for_status()  # Raise an exception for bad status codes
    return response.text
  except requests.exceptions.RequestException as e:
    print(f"An error occurred while loading the text: {e}")
    return None

url = "https://www.gutenberg.org/ebooks/13846.txt.utf-8"  # Example URL (replace with your desired URL)
corpus = load_text_from_web(url)
url = "https://www.gutenberg.org/ebooks/4650.txt.utf-8"  # Example URL (replace with your desired URL)
corpus = corpus + load_text_from_web(url)

caracteres = list(set(list(corpus)))
nb_caracteres = len(caracteres)
nb_bicaracteres = 256-nb_caracteres
bicaracteres = [item for item, _ in Counter(cut_string_into_pairs(corpus)).most_common(nb_bicaracteres)]
symboles = caracteres + bicaracteres
nb_symboles = len(symboles)

def gen_key(symboles):

  l=len(symboles)
  if l > 256:
    return False

  rnd.seed(1337)
  int_keys = rnd.sample(list(range(l)),l)
  dictionary = dict({})
  for s,k in zip(symboles,int_keys):
    dictionary[s]="{:08b}".format(k )
  return dictionary

dictionaire = gen_key(symboles)
print("Taille du dictionaire:",len(dictionaire))
print(dictionaire)

def M_vers_symboles(M, K, dictionnaire):
    encoded_text = []
    i = 0

    while i < len(M):
        # Vérifie les paires de caractères
        if i + 1 < len(M):
            pair = M[i] + M[i + 1]
            if pair in dictionnaire:
                encoded_text.append(pair)
                i += 2  # Sauter les deux caractères utilisés
                continue

        # Vérifie le caractère seul
        if M[i] in K:
            encoded_text.append(M[i])
        else:
            # Conserve le caractère tel quel si non trouvé
            encoded_text.append(M[i])
        i += 1

    return encoded_text

def chiffrer(M,K, dictionnaire):
  l = M_vers_symboles(M, K, dictionnaire)
  l = [K[x] for x in l]
  return ''.join(l)

def chiffrer2(M, K) -> str:
    """
    Encode le texte en utilisant un dictionnaire personnalisé.

    :param text: Le texte à encoder
    :param dictionnaire: Le dictionnaire de correspondances
    :return: Le texte encodé
    """
    encoded_text = []
    i = 0

    while i < len(M):
        # Vérifie les paires de caractères
        if i + 1 < len(M):
            pair = M[i] + M[i + 1]
            if pair in K:
                encoded_text.append(K[pair])
                i += 2  # Sauter les deux caractères utilisés
                continue

        # Vérifie le caractère seul
        if M[i] in K:
            encoded_text.append(K[M[i]])
        else:
            # Conserve le caractère tel quel si non trouvé
            encoded_text.append(M[i])
        i += 1

    return ''.join(encoded_text)

K = gen_key(symboles)
dictionnaire = gen_key(symboles)
M = corpus[12000:12100]
C = chiffrer(M, K,dictionnaire)

print("M ="+"\""+M+"\"")
print("\nLongeur du message M =",len(M))
print("\nDivision en symboles =", M_vers_symboles(M, K,dictionnaire))
print("\nNombre de symboles =", len(M_vers_symboles(M, K,dictionnaire)))
print("\nC = "+"\""+C+"\"")
print("\nLongeur du cryprogramme C en bits =",len(C))
print("\nLongeur du cryprogramme C en octets =",len(C)//8)

"""## L'idée est de créer un immense cryptogramme à partir d'un gros échantillon de texte français et d'analyser 
les fréquences d'apparition des blocs de bytes et les comparer avec la fréquence d'apparition des 
symboles dans la liste de symboles fixée et trouvée dans un grand échantillon de texte français pour 
créer une clé espérée qui devrait correspondre à la clé secrète originale qu'on ne connait pas"""

# Compte les fréquences des blocs de bytes dans un cryptogramme donné
def get_frequency_counts(ciphertext, segment_length=8):
    # Diviser le cryptogramme en bytes (8 bits)
    segments = [ciphertext[i:i + segment_length] for i in range(0, len(ciphertext), segment_length)]
    # Compte
    dist_segments = Counter(segments)

    return dist_segments

# Crée une clé espérée
def create_guess_key(ciphertext):
    # Fréquence des bytes
    ciphertext_chunk_freq = get_frequency_counts(ciphertext)
    reference_freq_dist = Counter(M_vers_symboles(corpus, symboles, symboles))

    # Mettre symboles et bytes en ordre décroissant d'apparition
    sorted_reference_symbols = sorted(reference_freq_dist.items(), key=lambda x: x[1], reverse=True)
    sorted_ciphertext_chunks = sorted(ciphertext_chunk_freq.items(), key=lambda x: x[1], reverse=True)

    # On met les symboles les plus fréquents avec les bytes les plus fréquents
    reversed_guess_key = {}
    for (symbol, _), (chunk, _) in zip(sorted_reference_symbols, sorted_ciphertext_chunks):
        reversed_guess_key[symbol] = chunk  # Flip the mapping

    return reversed_guess_key

def decrypt(C):
    url1 = "https://www.gutenberg.org/ebooks/13846.txt.utf-8"
    corpus1 = load_text_from_web(url1)

    # Charger le deuxième corpus et enlever les 10 000 premiers caractères
    url2 = "https://www.gutenberg.org/ebooks/4650.txt.utf-8"
    corpus2 = load_text_from_web(url2)

    # Combiner les deux corpus
    corpus = corpus1 + corpus2

    caracteres = list(set(list(corpus)))
    nb_caracteres = len(caracteres)
    nb_bicaracteres = 256 - nb_caracteres
    bicaracteres = [item for item, _ in Counter(cut_string_into_pairs(corpus)).most_common(nb_bicaracteres)]

    # Ces listes sont fixées pour le système
    symboles = ['b', 'j', '\r', 'J', '”', ')', 'Â', 'É', 'ê', '5', 't', '9', 'Y', '%', 'N', 'B', 'V', '\ufeff', 'Ê',
                '?', '’', 'i', ':', 's', 'C', 'â', 'ï', 'W', 'y', 'p', 'D', '—', '«', 'º', 'A', '3', 'n', '0', 'q', '4',
                'e', 'T', 'È', '$', 'U', 'v', '»', 'l', 'P', 'X', 'Z', 'À', 'ç', 'u', '…', 'î', 'L', 'k', 'E', 'R', '2',
                '_', '8', 'é', 'O', 'Î', '‘', 'a', 'F', 'H', 'c', '[', '(', "'", 'è', 'I', '/', '!', ' ', '°', 'S', '•',
                '#', 'x', 'à', 'g', '*', 'Q', 'w', '1', 'û', '7', 'G', 'm', '™', 'K', 'z', '\n', 'o', 'ù', ',', 'r',
                ']', '.', 'M', 'Ç', '“', 'h', '-', 'f', 'ë', '6', ';', 'd', 'ô', 'e ', 's ', 't ', 'es', ' d', '\r\n',
                'en', 'qu', ' l', 're', ' p', 'de', 'le', 'nt', 'on', ' c', ', ', ' e', 'ou', ' q', ' s', 'n ', 'ue',
                'an', 'te', ' a', 'ai', 'se', 'it', 'me', 'is', 'oi', 'r ', 'er', ' m', 'ce', 'ne', 'et', 'in', 'ns',
                ' n', 'ur', 'i ', 'a ', 'eu', 'co', 'tr', 'la', 'ar', 'ie', 'ui', 'us', 'ut', 'il', ' t', 'pa', 'au',
                'el', 'ti', 'st', 'un', 'em', 'ra', 'e,', 'so', 'or', 'l ', ' f', 'll', 'nd', ' j', 'si', 'ir', 'e\r',
                'ss', 'u ', 'po', 'ro', 'ri', 'pr', 's,', 'ma', ' v', ' i', 'di', ' r', 'vo', 'pe', 'to', 'ch', '. ',
                've', 'nc', 'om', ' o', 'je', 'no', 'rt', 'à ', 'lu', "'e", 'mo', 'ta', 'as', 'at', 'io', 's\r', 'sa',
                "u'", 'av', 'os', ' à', ' u', "l'", "'a", 'rs', 'pl', 'é ', '; ', 'ho', 'té', 'ét', 'fa', 'da', 'li',
                'su', 't\r', 'ée', 'ré', 'dé', 'ec', 'nn', 'mm', "'i", 'ca', 'uv', '\n\r', 'id', ' b', 'ni', 'bl']

    dictionnaire = gen_key(symboles)
    K = gen_key(symboles)
    
    # Séparer le cryptogramme en bytes
    chunks = [C[i:i + 8] for i in range(0, len(C), 8)]

    # Chiffrer grand texte pour une analyse exhaustive
    big_ciphertext = chiffrer(corpus, K, dictionnaire)
    guess_key = create_guess_key(big_ciphertext)

    # Remplacer chaque byte avec son symbole correspondant selon la clé espérée
    decrypted_text = []
    for chunk in chunks:
        symbol = next((key for key, value in guess_key.items() if value == chunk), '?')
        decrypted_text.append(symbol)

    # Jumeler le message
    return ''.join(decrypted_text)