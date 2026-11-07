#!/usr/bin/env python3
#usage basic pour du fuzzing :  python3 filess -u https://tesla.com/index.html 
#usage analyse de code source:  python3 filess -u https://tesla.com/index.html --source --json
#le mieux : filess -u https://tesla.com/html.com
#vous pouvez aussi l'ajouter a votre patch dans votre terminal et l'utiliser dans tout les répertoire en faisant " filess -u https://tela.com/index.php"

#by Pikachu :)

import time
import requests
import re
from rich.console import Console
import argparse
import json
from urllib.parse import urljoin
console = Console()

console.print("""
[bold cyan]
   ___ __ __                   
 .'  _|__|  .-----.-----.-----. Version 1.0
 |   _|  |  |  -__|__ --|__ --|
 |__| |__|__|_____|_____|_____|
                               
[/bold cyan]
[green]by Pikachu[/green]
[dim]                 FILESS[/dim]
[dim]          [yellow]OUtils de Web Recon & analyse de code Source coder par Pikachu[/yellow]  [/dim]
""")

parser = argparse.ArgumentParser(description="Analyse d'url et enumeration de point de terminaison")
parser.add_argument('-u', '--url', type=str, required=True, help='URL à analyser')
parser.add_argument('-t', '--timeout', type=int, default=5, help='timeout pour les requêtes en secondes')
parser.add_argument('-w', '--wordlist', type=str, required=False, help='chemin custom vers le fichier de wordlist')
parser.add_argument('-rl', '--rate-limit', type=int, default=1, help='limit de requêtes par seconde')
parser.add_argument('-r', '--recursive', action='store_true', help='brute force de répertoires et sous-repertoires')
parser.add_argument('-e', '--extensions', type=str, required=False, help='extention de fichier à rechercher (ex: .php, .html, .js)')
parser.add_argument('-ex', '--exclude-extension', type=str, required=False, help='exclusion de fichier non desiré (ex: .js; .svg, .pdf)')
parser.add_argument('-s', '--source', required=False, action='store_true', help='analyse de code source')
parser.add_argument('-j', '--json', action='store_true', help='enregistrement obliguatoire du code source analyser')

args = parser.parse_args()

def analyse_url(url):
    
    try:
        response = requests.get(url, timeout=args.timeout, allow_redirects=False)
        
        location = response.headers.get("Location", "[*]")
        if response.status_code == 200:
            console.print(f"[green]{url} : {response.status_code} [/green]")
        elif response.status_code in (403, 401):
            console.print(f"[red]{url} : {response.status_code} refusé [/red]")
        elif 300 <= response.status_code < 400:
            console.print(f"[yellow]{url} : {response.status_code}[/yellow] [blue] ->[/blue] [green]{location}[/green]")
        elif 400 <= response.status_code < 500 and response.status_code != 404:
            console.print(f"[red]{url} : {response.status_code} [/red]")
        
        return response
        
    except requests.ConnectionError:
        console.print(f"[red]{url} : connexion refusée [/red]")
    except requests.Timeout:
        console.print(f"[yellow]{url} : timeout[/yellow]")
    except requests.RequestException:
        console.print(f"[red]{url} : erreur réseau[/red]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
    
    return analyse_url


def enum(url):
    wordlist_path = args.wordlist or "/usr/local/share/filess-wordlist.txt"
    method = "GET"
    console.print(f"[bold purple][+] Cible : {url}[/bold purple] | HTTP method: {method} | [cyan] timeout : {args.timeout} | rate-limit : {args.rate_limit} [/cyan]")
    console.print("Tailles de la wordlist par defaut : +29k  ")
    time.sleep(1)
    console.print("fuzzing en cours...")
    time.sleep(1)

    try:
        with open(wordlist_path, "r", encoding="utf-8") as fichier:
            for ligne in fichier:
                ligne = ligne.strip()
                if not ligne or ligne.startswith('#'):
                    continue
                url_base = url.rstrip("/")
                url_path = f"{url_base}/{ligne}"
                analyse_url(url_path)
    except FileNotFoundError:
        console.print(f"[red]Fichier wordlist introuvable : {wordlist_path}[/red]")
    console.print("fuzzing terminer...")
    time.sleep(2)
    
def analyse_source(url):
    try:

        response = requests.get(url, timeout=args.timeout, allow_redirects=False)
        console.print(" ========== recherche de point sencible... ==========")
        time.sleep(3)
        if response.status_code != 200:
           
           console.print(f"[red][blue]{url}[/blue] : {response.status_code}[/red] — source non analysé")
        source = response.text
        print("Taille du source :", len(source))
        time.sleep(2)
        print("GraphQL :", "graphql" in source.lower())
        time.sleep(1)

        endpoints = re.findall(r'["\']([^"\']*(?:/api/|/graphql|/auth/|/login)[^"\']*)["\']', source, re.IGNORECASE)
        

        js_files = re.findall(
            r'<script[^>]+src=["\']([^"\']+)["\']', source, re.IGNORECASE
        )
        js_urls = [urljoin(url, js_file) for js_file in js_files]

        js_sources = []
        for js_url in js_urls:
            try:
                js_response = requests.get(
                    js_url, timeout=args.timeout, allow_redirects=False
                )
                if js_response.status_code == 200:
                    js_sources.append({
                        "url": js_url,
                        "source": js_response.text
                    })
            except requests.RequestException as e:
                console.print(f"[yellow]{js_url} : erreur réseau {e}[/yellow]")
        console.print("JS téléchargés :", len(js_sources))
        for js in js_sources:
            js_endpoints = re.findall(r'["\']([^"\']*(?:/api/|/graphql|/auth/|/login)[^"\']*)["\']',
                js["source"],
                re.IGNORECASE
            )
            if js_endpoints:
                console.print(f"\n[blue][JS][/blue][cyan] {js['url']}[/cyan]")


        if not endpoints:
            console.print("[red] [-]aucun point sencible detecter[/red]")


        if response.status_code == 200:
            if args.json:
                data = {
                    "url": url,
                    "status_code": response.status_code,
                    "server": response.headers.get("Server"),
                    "source_size": len(source),
                    "html_endpoints": list(set(endpoints)),
                    "js_files": js_sources
                }    
                with open("source.json", "w", encoding="utf-8") as fichier:
                    json.dump(data, fichier, ensure_ascii=False, indent=2)
                console.print("[green]Code source enregistré dans source.json[/green]")
                time.sleep(1)
        else:
            console.print(f"[blue]--------------------------------[/blue]")
    except requests.ConnectionError:
        console.print(f"[red]{url} : connexion refusée, veuillez verifier votre connexion avec ping [/red]")
    except requests.Timeout:
        console.print(f"[yellow]{url} : timeout[/yellow]")
    except requests.RequestException:
        console.print(f"[red]{url} : erreur réseau[/red]")
    except Exception as e:
        console.print(f"Error:", str({e}), markup=False)
    
enum(args.url)

if args.source:
    analyse_source(args.url)
    
