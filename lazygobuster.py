import subprocess
import os
import argparse
from urllib.parse import urljoin

# Fonction pour lancer gobuster sur un répertoire donné
def run_gobuster(url, wordlist, output_file):
    print(f"[+] Running gobuster on {url}")
    gobuster_command = f"gobuster dir -u {url} -w {wordlist} -s 200,204,301,302,307,403 --status-codes-blacklist '' -t 50 -e -o {output_file} -k"
    result = subprocess.run(gobuster_command, shell=True, text=True)
    
    # Vérifier si le fichier de sortie a été généré par gobuster
    if not os.path.isfile(output_file):
        print(f"[-] Error: Gobuster did not generate the output file {output_file}. Check the command or the URL.")
        return []

    # Lecture des résultats de gobuster
    with open(output_file, "r") as file:
        lines = file.readlines()
    
    # Retourne la liste des chemins trouvés qui ont un statut d'acceptation ou de redirection/interdiction
    return [line.split(" ")[0] for line in lines if any(status in line for status in ["Status: 200", "Status: 204", "Status: 301", "Status: 302", "Status: 307", "Status: 403"])]

# Fonction principale pour l'énumération récursive des répertoires
def enumerate_all_directories(base_url, wordlist, exclude_paths):
    visited_paths = set()  # Ensemble des chemins déjà visités
    paths_to_visit = [base_url]  # Liste des chemins à visiter

    while paths_to_visit:
        # On prend le prochain chemin à visiter et on l'utilise temporairement comme URL
        current_path = paths_to_visit.pop(0)
        current_url = current_path

        # Vérifie si le chemin actuel est dans la liste des chemins à ignorer
        if any(excluded in current_url for excluded in exclude_paths):
            print(f"[-] Skipping excluded path: {current_url}")
            continue

        if current_url in visited_paths:
            continue  # Si déjà visité, passe au suivant

        visited_paths.add(current_url)
        # Crée un fichier de sortie pour stocker les résultats de gobuster
        output_file = f"{output_dir}/{current_url.replace('https://', '').replace('/', '_')}.txt"

        # Énumère les sous-répertoires du chemin actuel
        found_paths = run_gobuster(current_url, wordlist, output_file)

        # Ajoute les nouveaux chemins trouvés à la liste des chemins à visiter
        for path in found_paths:
            # Utilise urljoin pour éviter les doublons dans les URLs
            full_url = urljoin(current_url.rstrip("/") + "/", path.lstrip("/"))
            if full_url not in visited_paths and full_url not in paths_to_visit:
                paths_to_visit.append(full_url)
                print(f"[+] New path found: {full_url}")

    return visited_paths

# Fonction pour énumérer tous les fichiers dans les répertoires trouvés
def enumerate_files_in_directories(paths, wordlist, exclude_paths):
    for path in paths:
        # Vérifie si le chemin actuel est dans la liste des chemins à ignorer
        if any(excluded in path for excluded in exclude_paths):
            print(f"[-] Skipping excluded path: {path}")
            continue

        print(f"[+] Enumerating files in {path}")
        # Crée un fichier de sortie pour chaque répertoire pour stocker les résultats
        output_file = f"{output_dir}/{path.replace('https://', '').replace('/', '_')}_files.txt"
        run_gobuster(path, wordlist, output_file)

# Configuration des options de ligne de commande
def parse_arguments():
    parser = argparse.ArgumentParser(description="Script de scan de répertoires et de fichiers pour un site donné")
    parser.add_argument("--host", required=True, help="L'adresse IP ou le nom de domaine du site cible (ex: container.cte-gie.fr)")
    parser.add_argument("--port", required=True, type=int, help="Le port du site cible (ex: 35906)")
    parser.add_argument("--path", default="", help="Le chemin de base sur le site (par défaut: '')")
    parser.add_argument("--dir-wordlist", default="/usr/share/wordlists/dirb/common2.txt", help="Chemin vers la wordlist pour les répertoires")
    parser.add_argument("--file-wordlist", default="/usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-files.txt", help="Chemin vers la wordlist pour les fichiers")
    parser.add_argument("--output-dir", default="enumeration_results", help="Dossier pour stocker les résultats")
    parser.add_argument("--exclude-paths", nargs='*', default=[], help="Liste des chemins à exclure de l'énumération (ex: /admin/login)")

    return parser.parse_args()

# Exécution principale du script
if __name__ == "__main__": 
    # Récupération des arguments
    args = parse_arguments()

    # Configuration de l'URL cible en utilisant les arguments de ligne de commande
    base_url = f"https://{args.host}:{args.port}"
    # Ajoute le chemin s'il est fourni, sinon utilise seulement `base_url`
    path = f"/{args.path}".replace("//", "/") if args.path and not args.path.startswith("/") else args.path
    target_url = f"{base_url}{path}".rstrip('/') + "/"
    
    print(f"[+] Target URL: {target_url}")  # Debug pour afficher l'URL cible initiale

    wordlist_dir = args.dir_wordlist  # Wordlist pour énumérer les répertoires
    wordlist_files = args.file_wordlist  # Wordlist orientée fichiers
    output_dir = args.output_dir  # Dossier pour stocker les résultats
    exclude_paths = args.exclude_paths  # Chemins à exclure

    # Crée le dossier de résultats s'il n'existe pas
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Énumération de tous les répertoires et sous-répertoires, en excluant certains chemins
    all_directories = enumerate_all_directories(target_url, wordlist_dir, exclude_paths)

    # Énumération de tous les fichiers dans les répertoires trouvés, en excluant certains chemins
    enumerate_files_in_directories(all_directories, wordlist_files, exclude_paths)

    print(f"[+] Enumeration completed. Results stored in {output_dir}.")
