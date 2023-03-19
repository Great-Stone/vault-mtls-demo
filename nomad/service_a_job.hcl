job "mtls-service-a" {
  datacenters = ["dc1"]

  type = "service"

  group "service" {
    count = 1

    network {
	    port "https" {
        static = 7433
      }
    }
    
    vault {
      namespace = ""
      policies = ["pki"]
      change_mode = "noop"
    }

    task "python-task" {
      driver = "raw_exec"

      config {
        command = "local/start.sh"
      }
      template {
        data = <<EOH
#!/bin/bash
cp -R /Users/gs/workspaces/hashicorp_example/vault-examples/mtls-pki/python_service_a python_service_a
cd python_service_a
pip install requests flask
python main.py
      EOH
				destination = "local/start.sh"
      }
      template {
        data = <<EOH
{{- /* ca-a.tpl */ -}}
{{ with secret "pki/issue/example-dot-com" "common_name=service-a.example.com" "ttl=2m" }}
{{ .Data.issuing_ca }}{{ end }}
      EOH
				destination = "/cert/ca.crt"
				change_mode = "noop"
      }
      template {
        data = <<EOH
{{- /* cert-a.tpl */ -}}
{{ with secret "pki/issue/example-dot-com" "common_name=service-a.example.com" "ttl=2m" }}
{{ .Data.certificate }}{{ end }}
      EOH
				destination = "/cert/service-a.crt"
				change_mode = "restart"
      }
      template {
        data = <<EOH
{{- /* key-a.tpl */ -}}
{{ with secret "pki/issue/example-dot-com" "common_name=service-a.example.com" "ttl=2m" }}
{{ .Data.private_key }}{{ end }}
      EOH
				destination = "/cert/service-a.key"
				change_mode = "noop"
      }
    }
  }
}