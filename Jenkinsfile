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
        sh './.jenkins_script.sh'
      }
    }
  }
}
