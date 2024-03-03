import tkinter as tk
from tkinter import messagebox, ttk
import string
import random
from cryptography.fernet import Fernet
import os
import hashlib


class MotDePasseMaitre(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent.root)
        self.parent = parent
        self.title("Mot de passe maître")

        self.label = ttk.Label(self, text="Veuillez entrer le mot de passe maître:")
        self.label.pack()

        self.entry = ttk.Entry(self, show="*")
        self.entry.pack()

        self.button = tk.Button(self, text="Valider", command=self.valider)
        self.button.pack()


    def valider(self):
        mot_de_passe_maitre = self.entry.get()

        hash_calculé = hashlib.sha256(mot_de_passe_maitre.encode()).hexdigest()

        with open('hash_mdp_maitre.txt', 'r') as file:
            hash_existant = file.read().strip()
        if hash_calculé == hash_existant:
            self.destroy()
            self.parent.root.deiconify() 
        else:
            tk.messagebox.showerror("Erreur", "Mot de passe maître incorrect.")

class OptionsDeMotDePasse(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent.root)
        self.parent = parent 

        self.var_longueur = tk.IntVar(value=12) 
        self.var_majuscules = tk.BooleanVar(value=True) 
        self.var_minuscules = tk.BooleanVar(value=True) 
        self.var_chiffres = tk.BooleanVar(value=True) 
        self.var_caracteres_speciaux = tk.BooleanVar(value=True)  

        self.label_longueur = tk.Label(self, text="Longueur:")
        self.label_longueur.pack()
        self.spin_longueur = tk.Spinbox(self, from_=4, to_=32, textvariable=self.var_longueur)
        self.spin_longueur.pack()

        self.check_majuscules = tk.Checkbutton(self, text="Inclure des majuscules", variable=self.var_majuscules)
        self.check_majuscules.pack()
        self.check_minuscules = tk.Checkbutton(self, text="Inclure des minuscules", variable=self.var_minuscules)
        self.check_minuscules.pack()
        self.check_chiffres = tk.Checkbutton(self, text="Inclure des chiffres", variable=self.var_chiffres)
        self.check_chiffres.pack()
        self.check_caracteres_speciaux = tk.Checkbutton(self, text="Inclure des caractères spéciaux", variable=self.var_caracteres_speciaux)
        self.check_caracteres_speciaux.pack()

        self.bouton_generer = tk.Button(self, text="Générer", command=lambda: parent.generer_mot_de_passe(
            self.var_longueur.get(),
            self.var_majuscules.get(),
            self.var_minuscules.get(),
            self.var_chiffres.get(),
            self.var_caracteres_speciaux.get()
        ))
        self.bouton_generer.pack()

class LeGestionnaireDeMotDePasse(tk.Frame):

    def __init__(self, root):
        self.root = root
        self.design()
        self.cle_chiffrement = self.generer_cle_chiffrement()

    def design(self):
        self.root.title("Gestionnaire de mots de passe")
        
        self.root.bind("<Return>", self.ajouter_mot_de_passe)
        self.root.bind("<Control-q>", lambda event: self.root.quit())
        self.root.bind("<Control-c>", lambda event: self.copy_to_clipboard(self.mot_de_passe_entree.get()))

        self.entry_frame = ttk.Frame(self.root)
        self.entry_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

        self.site_web_label = ttk.Label(self.entry_frame, text="Site Web:")
        self.site_web_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")

        self.site_web_entree = ttk.Entry(self.entry_frame, width=35)
        self.site_web_entree.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        self.nom_utilisateur_label = ttk.Label(self.entry_frame, text="Nom d'utilisateur:")
        self.nom_utilisateur_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")

        self.nom_utilisateur_entree = ttk.Entry(self.entry_frame, width=35)
        self.nom_utilisateur_entree.grid(row=1, column=1, padx=5, pady=5, sticky="ew")

        self.mot_de_passe_label = ttk.Label(self.entry_frame, text="Mot de passe:")
        self.mot_de_passe_label.grid(row=2, column=0, padx=5, pady=5, sticky="w")

        self.mot_de_passe_entree = ttk.Entry(self.entry_frame, width=35, show="*")
        self.mot_de_passe_entree.grid(row=2, column=1, padx=5, pady=5, sticky="ew")

        self.button_frame = ttk.Frame(self.root)
        self.button_frame.grid(row=1, column=0, pady=10, sticky="ew")

        self.generer_mot_de_passe_bouton = tk.Button(self.button_frame, text="Générer Mot de Passe Aléatoire", command=self.ouvrir_options_de_mot_de_passe)
        self.generer_mot_de_passe_bouton.grid(row=0, column=0, padx=5, pady=5, sticky="ew")

        self.ajouter_bouton = tk.Button(self.button_frame, text="Ajouter", command=self.ajouter_mot_de_passe)
        self.ajouter_bouton.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        self.button = tk.Button(self.button_frame, text="Theme", command=self.change_theme)
        self.button.grid(row=0, column=2, padx=5, pady=5, sticky="ew")

        self.consulter_bouton = tk.Button(self.button_frame, text="Consulter", command=self.lancer_consultation)
        self.consulter_bouton.grid(row=0, column=3, padx=5, pady=5, sticky="ew")

        self.entry_frame.columnconfigure(1, weight=1)
        self.button_frame.columnconfigure(0, weight=1)
        self.button_frame.columnconfigure(1, weight=1)
        self.button_frame.columnconfigure(2, weight=1)
        self.button_frame.columnconfigure(3, weight=1)

        self.root.tk.call("source", "park.tcl")
        self.root.tk.call("set_theme", "light")


    def ouvrir_options_de_mot_de_passe(self):
        OptionsDeMotDePasse(self)

    def generer_mot_de_passe(self, longueur=12, majuscules=True, minuscules=True, chiffres=True, caracteres_speciaux=True):
        caracteres = ''
        if majuscules:
            caracteres += string.ascii_uppercase
        if minuscules:
            caracteres += string.ascii_lowercase
        if chiffres:
            caracteres += string.digits
        if caracteres_speciaux:
            caracteres += string.punctuation

        mot_de_passe = ''.join(random.choice(caracteres) for _ in range(longueur))
        self.mot_de_passe_entree.delete(0, tk.END)
        self.mot_de_passe_entree.insert(0, mot_de_passe)
        self.mot_de_passe_label.config(text="Mot de passe généré : " + mot_de_passe)


    def chiffrer_mot_de_passe(self, mot_de_passe):
        fernet = Fernet(self.obtenir_cle_chiffrement())
        return fernet.encrypt(mot_de_passe.encode()).decode()
    
    def dechiffrer_mot_de_passe(self, mot_de_passe_chiffre):
        fernet = Fernet(self.obtenir_cle_chiffrement())
        return fernet.decrypt(mot_de_passe_chiffre.encode()).decode()
    
    def change_theme(self):
        if self.root.tk.call("ttk::style", "theme", "use") == "park-dark":
            self.root.tk.call("set_theme", "light")
        else:
            self.root.tk.call("set_theme", "dark")

    def ajouter_mot_de_passe(self, event=None ):
        
        site_web = self.site_web_entree.get()
        nom_utilisateur = self.nom_utilisateur_entree.get()
        mot_de_passe = self.mot_de_passe_entree.get()

        if site_web == "" or nom_utilisateur == "" or mot_de_passe == "":
            messagebox.showerror("Erreur", "Veuillez remplir tous les champs.")
        else:
            mot_de_passe_chiffre = self.achiffrer(mot_de_passe, self.cle_chiffrement)

            with open("mots_de_passe.txt", "a") as fichier:
                fichier.write(f"{site_web} | {nom_utilisateur} | {mot_de_passe_chiffre}\n")
                self.site_web_entree.delete(0, tk.END)
                self.nom_utilisateur_entree.delete(0, tk.END)
                self.mot_de_passe_entree.delete(0, tk.END)
                messagebox.showinfo("Succès", "Mot de passe ajouté avec succès.")

    def generer_cle_chiffrement(self):
        if not os.path.isfile("cle_chiffrement.txt"):
            cle_chiffrement = Fernet.generate_key()
            with open("cle_chiffrement.txt", "wb") as fichier_cle:
                fichier_cle.write(cle_chiffrement)
        else:
            with open("cle_chiffrement.txt", "rb") as fichier_cle:
                cle_chiffrement = fichier_cle.read()
        return cle_chiffrement
    
    def lire_cle_chiffrement(self):
        with open("cle_chiffrement.txt", "rb") as fichier:
            return fichier.read()

    def lancer_consultation(self):
            consultation_window = tk.Toplevel(self.root)
            consultation_window.title("Fenêtre consultation")

            tree = ttk.Treeview(consultation_window, columns=('Site Web', 'Nom d’utilisateur', 'Mot de passe'), show='headings')
            tree.heading('Site Web', text='Site Web')
            tree.heading('Nom d’utilisateur', text='Nom d’utilisateur')
            tree.heading('Mot de passe', text='Mot de passe')
            tree.grid(row=0, column=0, padx=10, pady=10, columnspan=3, sticky="nsew")

            scrollbar = ttk.Scrollbar(consultation_window, orient=tk.VERTICAL, command=tree.yview)
            scrollbar.grid(row=0, column=3, sticky='ns')
            tree.config(yscrollcommand=scrollbar.set)

            with open("mots_de_passe.txt", "r") as fichier:
                contenu = fichier.readlines()

            for ligne in contenu:
                if ligne.strip():
                    champs = ligne.strip().split(" | ")
                    if len(champs) >= 3:
                        site_web, nom_utilisateur, mot_de_passe_chiffre = champs
                        mot_de_passe = self.adechiffrer(mot_de_passe_chiffre, self.cle_chiffrement)
                        tree.insert('', tk.END, values=(site_web, nom_utilisateur, mot_de_passe))

            button_frame = ttk.Frame(consultation_window)
            button_frame.grid(row=1, column=0, padx=10, pady=10, columnspan=3, sticky="ew")

            copy_username_button = ttk.Button(button_frame, text="Copier Nom d'utilisateur", command=lambda: self.copy_to_clipboard(tree.item(tree.selection())['values'][1]))
            copy_username_button.pack(side=tk.LEFT, padx=5, pady=5)

            copy_password_button = ttk.Button(button_frame, text="Copier Mot de passe",command=lambda: self.copy_to_clipboard(tree.item(tree.selection())['values'][2]))
            copy_password_button.pack(side=tk.LEFT, padx=5, pady=5)

            delete_button = ttk.Button(button_frame, text="Supprimer",command=lambda: self.supprimer_mot_de_passe(tree.item(tree.selection())['values'],consultation_window))
            delete_button.pack(side=tk.LEFT, padx=5, pady=5)

            consultation_window.mainloop()


    def supprimer_mot_de_passe(self, values, consultation_window):
        consultation_window.destroy()
        if messagebox.askyesno("Confirmation", "Voulez-vous vraiment supprimer ce mot de passe ?"):
            site_web, nom_utilisateur, _ = values  
            with open("mots_de_passe.txt", "r") as fichier:
                lines = fichier.readlines()

            with open("mots_de_passe.txt", "w") as fichier:
                for line in lines:
                    champs = line.strip().split(" | ")
                    if champs[0] != site_web or champs[1] != nom_utilisateur:
                        fichier.write(line)

            self.lancer_consultation()

    def achiffrer(self, message, cle_chiffrement):
        f = Fernet(cle_chiffrement)
        message_chiffre = f.encrypt(message.encode())
        return message_chiffre.decode()

    def adechiffrer(self, message_chiffre, cle_chiffrement):
        f = Fernet(cle_chiffrement)
        message_decrypte = f.decrypt(message_chiffre.encode())
        return message_decrypte.decode()

    def copy_to_clipboard(self, text_to_copy, event=None):
        self.root.clipboard_clear()
        self.root.clipboard_append(text_to_copy)
        self.root.update()

if __name__ == "__main__":
    root = tk.Tk()
    root.withdraw()
    app = LeGestionnaireDeMotDePasse(root)
    MotDePasseMaitre(app)     
    root.mainloop()
