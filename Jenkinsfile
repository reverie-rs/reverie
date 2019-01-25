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
        sh 'srun -N1 -t 1:00:00 --exclusive "./.jenkins_script.sh"'
      }
    }
  }
}
