job "mtls-service-b" {
  datacenters = ["dc1"]

  type = "service"

  group "service" {
    count = 1

    network {
	    port "https" {
        static = 8433
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
cp -R /Users/gs/workspaces/hashicorp_example/vault-examples/mtls-pki/python_service_b python_service_b
cd python_service_b
pip install requests flask
python main.py
      EOH
				destination = "local/start.sh"
      }
      template {
        data = <<EOH
{{- /* ca-a.tpl */ -}}
{{ with secret "pki/issue/example-dot-com" "common_name=service-b.example.com" "ttl=2m" }}
{{ .Data.issuing_ca }}{{ end }}
      EOH
				destination = "/cert/ca.crt"
				change_mode = "noop"
      }
      template {
        data = <<EOH
{{- /* cert-a.tpl */ -}}
{{ with secret "pki/issue/example-dot-com" "common_name=service-b.example.com" "ttl=2m" }}
{{ .Data.certificate }}{{ end }}
      EOH
				destination = "/cert/service-b.crt"
				change_mode = "restart"
      }
      template {
        data = <<EOH
{{- /* key-a.tpl */ -}}
{{ with secret "pki/issue/example-dot-com" "common_name=service-b.example.com" "ttl=2m" }}
{{ .Data.private_key }}{{ end }}
      EOH
				destination = "/cert/service-b.key"
				change_mode = "noop"
      }
    }
  }
}