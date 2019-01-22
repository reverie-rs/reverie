pipeline {
  // This is designed to run on Cutter @ IU
  agent {
    label 'acghaswellcat16-label'
  }

  triggers {
      // Try to create a webhook:
      pollSCM('')
  }

  stages {
    stage('Build') {
      steps {
        // Warning: this has global side effects.  Cannot run twice on one machine:
        source .jenkins_script.sh
      }
    }
  }
}
