# Instructions pour résoudre les erreurs de supertypes Kotlin

## Problème
Le compilateur Kotlin dans IntelliJ IDEA ne peut pas résoudre les supertypes Java (java.lang.Object, java.lang.Enum, etc.)

## Solution appliquée

### 1. Fichiers modifiés
- **pom.xml** : Ajout de `-Xextended-compiler-checks` et configuration correcte de `jvmTarget`
- **.idea/kotlinc.xml** : Configuration du compilateur Kotlin avec jvmTarget 17
- **.mvn/jvm.config** : Configuration de la mémoire JVM pour Maven

### 2. Actions à effectuer dans IntelliJ IDEA

#### Option A - Recharger le projet Maven (RECOMMANDÉ)
1. Cliquez avec le bouton droit sur `pom.xml`
2. Sélectionnez **"Maven"** → **"Reload project"**
3. Attendez que l'indexation se termine

#### Option B - Invalider les caches
1. Menu **File** → **Invalidate Caches / Restart**
2. Cochez **"Invalidate and Restart"**
3. Cliquez sur **"Invalidate and Restart"**

#### Option C - Via la vue Maven
1. Ouvrez la vue **Maven** (côté droit de l'IDE)
2. Cliquez sur l'icône de rafraîchissement 🔄

### 3. Vérification
Après le rechargement :
- Les erreurs de supertypes devraient disparaître
- Le code devrait compiler sans erreur
- L'autocomplétion devrait fonctionner correctement

### 4. Si le problème persiste
Exécutez dans le terminal IntelliJ :
```powershell
mvn clean compile
```

Puis rechargez le projet Maven.

