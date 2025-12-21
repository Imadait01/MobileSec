// Script de test complet pour CIConnector
const app = require('./src/app');
const http = require('http');

let server;

// Démarrer le serveur
const PORT = 3001; // Utiliser un port différent pour les tests
server = app.listen(PORT, () => {
  console.log(`\n🧪 Serveur de test démarré sur le port ${PORT}\n`);
  runTests();
});

function makeRequest(path, method = 'GET', data = null) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: 'localhost',
      port: PORT,
      path: path,
      method: method,
      headers: {
        'Content-Type': 'application/json',
      }
    };

    const req = http.request(options, (res) => {
      let responseData = '';
      res.on('data', chunk => responseData += chunk);
      res.on('end', () => {
        try {
          resolve({
            status: res.statusCode,
            data: JSON.parse(responseData)
          });
        } catch {
          resolve({
            status: res.statusCode,
            data: responseData
          });
        }
      });
    });

    req.on('error', reject);

    if (data) {
      req.write(JSON.stringify(data));
    }
    req.end();
  });
}

async function runTests() {
  console.log('═══════════════════════════════════════════════════════════');
  console.log('   TESTS DU SERVICE CI-CONNECTOR');
  console.log('═══════════════════════════════════════════════════════════\n');

  let passed = 0;
  let failed = 0;

  // Test 1: Endpoint racine
  console.log('📋 Test 1: GET / (Statut du service)');
  try {
    const res = await makeRequest('/');
    if (res.status === 200 && res.data.service === 'CIConnector') {
      console.log('   ✅ Statut: 200');
      console.log('   ✅ Service:', res.data.service);
      console.log('   ✅ Version:', res.data.version);
      console.log('   ✅ Statut:', res.data.status);
      passed++;
    } else {
      console.log('   ❌ Échec');
      failed++;
    }
  } catch (error) {
    console.log('   ❌ Erreur:', error.message);
    failed++;
  }

  console.log('\n───────────────────────────────────────────────────────────\n');

  // Test 2: Trigger sans paramètres
  console.log('📋 Test 2: POST /api/trigger (sans paramètres)');
  try {
    const res = await makeRequest('/api/trigger', 'POST', {});
    if (res.status === 400 && res.data.error) {
      console.log('   ✅ Statut: 400 (attendu)');
      console.log('   ✅ Erreur:', res.data.error);
      passed++;
    } else {
      console.log('   ❌ Échec');
      failed++;
    }
  } catch (error) {
    console.log('   ❌ Erreur:', error.message);
    failed++;
  }

  console.log('\n───────────────────────────────────────────────────────────\n');

  // Test 3: Trigger avec fichier inexistant
  console.log('📋 Test 3: POST /api/trigger (fichier inexistant)');
  try {
    const res = await makeRequest('/api/trigger', 'POST', {
      apkPath: '/path/to/nonexistent.apk'
    });
    if (res.status === 404 && res.data.error === 'File not found') {
      console.log('   ✅ Statut: 404 (attendu)');
      console.log('   ✅ Erreur:', res.data.error);
      passed++;
    } else {
      console.log('   ❌ Échec');
      failed++;
    }
  } catch (error) {
    console.log('   ❌ Erreur:', error.message);
    failed++;
  }

  console.log('\n───────────────────────────────────────────────────────────\n');

  // Test 4: Génération CI/CD GitHub
  console.log('📋 Test 4: POST /api/generate-ci (GitHub)');
  try {
    const res = await makeRequest('/api/generate-ci', 'POST', {
      platform: 'github'
    });
    if (res.status === 200 && res.data.files) {
      console.log('   ✅ Statut: 200');
      console.log('   ✅ Statut:', res.data.status);
      console.log('   ✅ Fichiers générés:', res.data.files.length);
      console.log('   ✅ Message:', res.data.message);
      passed++;
    } else {
      console.log('   ❌ Échec:', res.data);
      failed++;
    }
  } catch (error) {
    console.log('   ❌ Erreur:', error.message);
    failed++;
  }

  console.log('\n───────────────────────────────────────────────────────────\n');

  // Test 5: Génération CI/CD GitLab
  console.log('📋 Test 5: POST /api/generate-ci (GitLab)');
  try {
    const res = await makeRequest('/api/generate-ci', 'POST', {
      platform: 'gitlab'
    });
    if (res.status === 200 && res.data.files) {
      console.log('   ✅ Statut: 200');
      console.log('   ✅ Statut:', res.data.status);
      console.log('   ✅ Fichiers générés:', res.data.files.length);
      passed++;
    } else {
      console.log('   ❌ Échec');
      failed++;
    }
  } catch (error) {
    console.log('   ❌ Erreur:', error.message);
    failed++;
  }

  console.log('\n───────────────────────────────────────────────────────────\n');

  // Test 6: Route inexistante
  console.log('📋 Test 6: GET /route-inexistante (404)');
  try {
    const res = await makeRequest('/route-inexistante');
    if (res.status === 404) {
      console.log('   ✅ Statut: 404 (attendu)');
      console.log('   ✅ Erreur:', res.data.error);
      passed++;
    } else {
      console.log('   ❌ Échec');
      failed++;
    }
  } catch (error) {
    console.log('   ❌ Erreur:', error.message);
    failed++;
  }

  // Résultats
  console.log('\n═══════════════════════════════════════════════════════════');
  console.log('   RÉSULTATS DES TESTS');
  console.log('═══════════════════════════════════════════════════════════\n');
  console.log(`   ✅ Tests réussis: ${passed}`);
  console.log(`   ❌ Tests échoués: ${failed}`);
  console.log(`   📊 Total: ${passed + failed}`);
  console.log(`   🎯 Taux de réussite: ${((passed / (passed + failed)) * 100).toFixed(1)}%`);
  console.log('\n═══════════════════════════════════════════════════════════\n');

  // Fermer le serveur
  server.close(() => {
    console.log('✅ Serveur de test arrêté\n');
    process.exit(failed > 0 ? 1 : 0);
  });
}
