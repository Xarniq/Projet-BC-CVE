#!/usr/bin/env python3
"""
Serveur web léger pour le Dashboard CVE
Usage: python serve.py [port]

Le serveur sert les fichiers statiques du build React.
"""
import http.server
import socketserver
import os
import sys

# Configuration
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
DIRECTORY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "shadcn-dashboard", "dist")

class SPAHandler(http.server.SimpleHTTPRequestHandler):
    """Handler qui redirige vers index.html pour le routing SPA"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)
    
    def do_GET(self):
        # Si le fichier n'existe pas et ce n'est pas un fichier statique, servir index.html
        path = self.translate_path(self.path)
        if not os.path.exists(path) and not self.path.startswith('/assets/'):
            self.path = '/index.html'
        return super().do_GET()
    
    def log_message(self, format, *args):
        # Log minimal
        print(f"[{self.log_date_time_string()}] {args[0]}")

def main():
    # Vérifier que le build existe
    if not os.path.exists(DIRECTORY):
        print(f"❌ Erreur: Le dossier {DIRECTORY} n'existe pas.")
        print("   Exécutez d'abord: cd shadcn-dashboard && npm run build")
        sys.exit(1)
    
    if not os.path.exists(os.path.join(DIRECTORY, "index.html")):
        print(f"❌ Erreur: index.html non trouvé dans {DIRECTORY}")
        print("   Exécutez d'abord: cd shadcn-dashboard && npm run build")
        sys.exit(1)
    
    # Démarrer le serveur
    with socketserver.TCPServer(("", PORT), SPAHandler) as httpd:
        print(f"""
╔═══════════════════════════════════════════════════════╗
║         🛡️  Dashboard CVE - Serveur Local             ║
╠═══════════════════════════════════════════════════════╣
║                                                       ║
║   🌐 URL: http://localhost:{PORT:<5}                    ║
║   📁 Dossier: {DIRECTORY[:35]:<35} ║
║                                                       ║
║   Glissez vos fichiers JSON d'audit pour commencer   ║
║   Appuyez sur Ctrl+C pour arrêter                    ║
║                                                       ║
╚═══════════════════════════════════════════════════════╝
""")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n👋 Serveur arrêté.")

if __name__ == "__main__":
    main()
