const yaml = require('js-yaml');

/**
 * Service pour générer les fichiers de configuration CI/CD
 */
class YamlGenerator {
  /**
   * Génère le fichier de configuration pour GitHub Actions
   * @returns {string} - Contenu YAML pour GitHub Actions
   */
  generateGitHubActions() {
    const config = {
      name: 'Security Scan',
      
      on: {
        push: {
          branches: ['main', 'develop']
        },
        pull_request: {
          branches: ['main', 'develop']
        },
        workflow_dispatch: null
      },

      jobs: {
        'security-scan': {
          'runs-on': 'ubuntu-latest',
          
          steps: [
            {
              name: 'Checkout code',
              uses: 'actions/checkout@v4'
            },
            {
              name: 'Set up Docker',
              uses: 'docker/setup-buildx-action@v3'
            },
            {
              name: 'Find APK/AAB files',
              id: 'find-apk',
              run: 'echo "apk_path=$(find . -type f \\( -name "*.apk" -o -name "*.aab" \\) | head -n 1)" >> $GITHUB_OUTPUT'
            },
            {
              name: 'Pull APKScanner image',
              run: 'docker pull apk-scanner:latest || echo "Image not found, skipping..."'
            },
            {
              name: 'Pull NetworkInspector image',
              run: 'docker pull network-inspector:latest || echo "Image not found, skipping..."'
            },
            {
              name: 'Run APKScanner',
              if: 'steps.find-apk.outputs.apk_path != \'\'',
              run: [
                'docker run --rm \\',
                '  -v "$(pwd):/app/input" \\',
                '  -v "apk-scanner-output:/app/output" \\',
                '  apk-scanner:latest \\',
                '  ${{ steps.find-apk.outputs.apk_path }}'
              ].join('\n')
            },
            {
              name: 'Run NetworkInspector',
              if: 'steps.find-apk.outputs.apk_path != \'\'',
              run: [
                'docker run --rm \\',
                '  -v "$(pwd):/app/input" \\',
                '  -v "network-inspector-output:/app/output" \\',
                '  network-inspector:latest \\',
                '  ${{ steps.find-apk.outputs.apk_path }}'
              ].join('\n')
            },
            {
              name: 'Upload scan results',
              if: 'always()',
              uses: 'actions/upload-artifact@v4',
              with: {
                name: 'security-scan-results',
                path: 'scan-results/',
                'retention-days': 30
              }
            },
            {
              name: 'Notify on failure',
              if: 'failure()',
              run: 'echo "Security scan failed! Please check the results."'
            }
          ]
        }
      }
    };

    return yaml.dump(config, {
      indent: 2,
      lineWidth: -1,
      noRefs: true,
      sortKeys: false
    });
  }

  /**
   * Génère le fichier de configuration pour GitLab CI
   * @returns {string} - Contenu YAML pour GitLab CI
   */
  generateGitLabCI() {
    const config = {
      image: 'docker:latest',

      services: ['docker:dind'],

      variables: {
        DOCKER_DRIVER: 'overlay2',
        DOCKER_TLS_CERTDIR: '/certs'
      },

      stages: ['security-scan', 'report'],

      before_script: [
        'docker info',
        'apk add --no-cache findutils'
      ],

      'security-scan:apk': {
        stage: 'security-scan',
        script: [
          'echo "Finding APK/AAB files..."',
          'export APK_PATH=$(find . -type f \\( -name "*.apk" -o -name "*.aab" \\) | head -n 1)',
          'echo "APK Path: $APK_PATH"',
          'if [ -z "$APK_PATH" ]; then',
          '  echo "No APK/AAB file found"',
          '  exit 1',
          'fi',
          'echo "Pulling APKScanner image..."',
          'docker pull apk-scanner:latest || echo "Image not available"',
          'echo "Running APKScanner..."',
          'docker run --rm \\',
          '  -v "$(pwd):/app/input" \\',
          '  -v "apk-scanner-output:/app/output" \\',
          '  apk-scanner:latest \\',
          '  $APK_PATH'
        ],
        artifacts: {
          paths: ['scan-results/'],
          expire_in: '30 days'
        },
        only: ['main', 'develop', 'merge_requests']
      },

      'security-scan:network': {
        stage: 'security-scan',
        script: [
          'echo "Finding APK/AAB files..."',
          'export APK_PATH=$(find . -type f \\( -name "*.apk" -o -name "*.aab" \\) | head -n 1)',
          'echo "APK Path: $APK_PATH"',
          'if [ -z "$APK_PATH" ]; then',
          '  echo "No APK/AAB file found"',
          '  exit 1',
          'fi',
          'echo "Pulling NetworkInspector image..."',
          'docker pull network-inspector:latest || echo "Image not available"',
          'echo "Running NetworkInspector..."',
          'docker run --rm \\',
          '  -v "$(pwd):/app/input" \\',
          '  -v "network-inspector-output:/app/output" \\',
          '  network-inspector:latest \\',
          '  $APK_PATH'
        ],
        artifacts: {
          paths: ['scan-results/'],
          expire_in: '30 days'
        },
        only: ['main', 'develop', 'merge_requests']
      },

      'report:summary': {
        stage: 'report',
        script: [
          'echo "==================================="',
          'echo "Security Scan Summary"',
          'echo "==================================="',
          'echo "Scan completed successfully"',
          'echo "Check artifacts for detailed results"'
        ],
        dependencies: ['security-scan:apk', 'security-scan:network'],
        only: ['main', 'develop', 'merge_requests']
      }
    };

    return yaml.dump(config, {
      indent: 2,
      lineWidth: -1,
      noRefs: true,
      sortKeys: false
    });
  }

  /**
   * Génère une configuration personnalisée
   * @param {string} platform - La plateforme cible (github ou gitlab)
   * @param {Object} options - Options personnalisées
   * @returns {string} - Contenu YAML personnalisé
   */
  generateCustom(platform, options = {}) {
    if (platform === 'github') {
      return this.generateGitHubActions();
    } else if (platform === 'gitlab') {
      return this.generateGitLabCI();
    } else {
      throw new Error(`Unsupported platform: ${platform}`);
    }
  }

  /**
   * Valide un fichier YAML
   * @param {string} yamlContent - Contenu YAML à valider
   * @returns {boolean} - True si valide, sinon lance une erreur
   */
  validateYaml(yamlContent) {
    try {
      yaml.load(yamlContent);
      return true;
    } catch (error) {
      throw new Error(`Invalid YAML: ${error.message}`);
    }
  }
}

module.exports = new YamlGenerator();
