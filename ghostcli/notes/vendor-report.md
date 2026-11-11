Subject: [segurança + performance] /v1/models sem autenticação, streaming bufferizado, 502 no GLM e em imagens

Olá,

Sou usuário do GhostCLI (chave gcli_-K9CI…ApRA) e reporto alguns comportamentos que acho que
não são intencionais. Tudo foi observado com requisições normais e documentadas — nenhum teste
de intrusão foi feito, e nada aqui foi explorado além da leitura. Sem detalhes de exploração
porque não há exploit: são respostas que a API já devolve.

1) GET https://ghostcli.cloud/v1/models responde 200 sem nenhum cabeçalho de autenticação
   (também com uma chave inválida). Cada item traz 30 campos internos, incluindo:
   - base_instructions (o prompt de sistema do modelo, ~485 caracteres)
   - priority (ordem de fila interna; 0–4 e 103/104 para as variantes [1m])
   - truncation_policy, shell_type, apply_patch_tool_type, minimal_client_version
   - o slug z-ai/glm-5.3 e z-ai/glm-5.3[1m], que não aparecem na documentação
   Sugestão: exigir chave válida e limitar o payload ao que o cliente precisa
   (id, display_name, context_window, max_output_tokens).

2) Substituição silenciosa de modelo. Verificado em GET /v1/models/{id}:
   - claude-haiku-4-5, claude-haiku-4-5-20251001, claude-3-5-haiku-latest,
     claude-3-5-haiku-20241022, claude-3-haiku-20240307 → todos resolvem para claude-sonnet-5
   - claude-opus-5-5[1m], claude-sonnet-5[1m], claude-fable-5.1[1m] → 200, mas o id volta sem
     o sufixo e context_window continua 256000. Quem pede 1M recebe 256k sem aviso.
   - gpt-6-astra → devolve gpt-6-astra[1m]
   Sugestão: recusar (400) o que não existe em vez de redirecionar, ou devolver um campo
   explícito dizendo para qual modelo a requisição foi mapeada.

3) GET /v1/models/z-ai/glm-5.3 devolve {"code":"unknown_route"} porque a rota aceita só um
   segmento. O id funciona em "model:" mas não é recuperável por id — quebra quem usa
   models.retrieve() de SDKs OpenAI. Sugestão: aceitar id URL-encoded.

Dois pontos que NÃO testei e que vale vocês conferirem internamente:
   - GET/DELETE /api/keys/ips recebem keyId/id vindos do cliente; confirmar que há checagem
     de propriedade no servidor.
   - o formulário de autorização de IP usa https://ipapi.co/json/ no navegador; confirmar que
     o IP gravado vem do socket e não do valor enviado pelo cliente.

4) Fila e streaming: com "stream": true a resposta inteira chega em um único delta de texto
   no final (medido: 229 caracteres, primeiro delta em 6,05 s = fim da resposta). Isso quebra
   a expectativa de qualquer cliente que use streaming para timeout ou feedback, e explica
   relatos de "travou". Sugestão: repassar o SSE do upstream sem buffer.

5) Latência fixa e erros de upstream:
   - toda chamada de modelo Claude paga ~2,2 s só para receber os headers (o astra paga 0,2 s);
   - apareceu 429 com corpo em português ("O upstream está congestionado") e um stall de 65 s
     na mesma pergunta curta — parece capacidade compartilhada, não fila por modelo.
   - z-ai/glm-5.3 e z-ai/glm-5.3[1m] (e o alias gpt-5.6-sol) devolvem 502 após 57–67 s em
     /v1/messages, /v1/chat/completions e /v1/responses; no streaming só chegam ": ping".
   - entrada de imagem devolve 502 nas três rotas, apesar de input_modalities ["text","image"]
     em todos os modelos do catálogo; o mesmo modelo com texto puro responde 200.

6) Métricas de uso: usage.input_tokens não conta o prompt de sistema enviado pelo cliente
   (2.100 tokens de system → input_tokens: 15, com o conteúdo claramente obedecido), e os
   campos de cache (cache_read_input_tokens / cache_creation_input_tokens) não voltam. Isso
   impede qualquer controle de custo do lado de quem integra. Sugestão: repassar o usage do
   upstream sem filtrar campos.

7) Entitlement: a chave que uso responde 200 em /v1/messages, mas a conta logada no dashboard
   mostra plano "free", api.active false, /api/keys vazio e /api/usage zerado em todos os dias.
   Ou seja, a inferência está fora do controle de entitlement/metragem da conta. Não explorei
   isso — apenas notei a inconsistência ao conferir meus próprios dados. Vale confirmar se é
   esperado que uma chave sem conta associada continue funcionando após o fim do plano.

Nada disso me impede de usar o serviço. Se quiserem, posso reproduzir qualquer item com curl
e mandar a saída. Não publiquei nada e não pretendo.

Obrigado,
<nome / e-mail da conta>
