# **Manual de Utilização:  `backup_integrity.py `**

Este script em Python ( `backup_integrity.py `) foi desenvolvido para **garantir a integridade de backups,** criando  `checksums ` e analisando se arquivos do backup foram eliminados ou acrescentados.  

Ele funciona criando um "inventário" (`manifesto`) detalhado dos arquivos e das suas assinaturas digitais (`hashes`) num determinado momento. Posteriormente, ele usa esse manifesto para verificar se houve alguma alteração não autorizada, corrupção de dados ou perda de arquivos.  

O script tem dois comandos: 
* O comando `gerar` varre um diretório-alvo gerando um manifesto (JSON) contendo metadados e o checksum de cada arquivo. 
* O comando `verificar` utiliza esse manifesto para comparar o estado atual do diretório com o estado salvo, reportando arquivos alterados, corrompidos, ausentes ou recém-adicionados.

A utilização de `checksums` (somas de verificação) é de suma importância neste processo, pois eles atuam como "impressões digitais" criptográficas dos dados. Qualquer mínima alteração no conteúdo de um arquivo — seja por *bit rot* (degradação natural da mídia), interrupção durante a cópia ou ação de malwares — resultará num *checksum* completamente diferente, permitindo a detecção matemática e incontestável da perda de integridade, mesmo que o tamanho e a data de modificação do arquivo permaneçam idênticos.

## **Casos de Uso Práticos**

* **Auditoria de Backups a Frio (Cold Storage):** Gerar o manifesto num HD externo. Meses depois, rodar a verificação para garantir que nenhum arquivo sofreu degradação magnética (*bit rot*).  
* **Prova de Cópia Exata (Transferências):** Se você precisa copiar a "Pasta X" para a "Pasta Y" e quer ter a certeza absoluta de que tudo foi copiado perfeitamente:  
  1. Gere o manifesto na "Pasta X".  
  2. Copie os arquivos e o manifesto gerado para a "Pasta Y".  
  3. Rode a verificação na "Pasta Y". Se não houver alertas, é a **prova criptográfica** de que a cópia foi 100% idêntica bit a bit. O script não dá falsos positivos mesmo que as datas de modificação dos arquivos tenham sido alteradas durante a cópia, pois ele avalia o caminho relativo e o conteúdo (hash).

## **1\. Comando `gerar` (Criação do Manifesto)**

O subcomando `gerar` mapeia recursivamente um diretório e calcula os hashes de todos os arquivos.  

**Sintaxe Básica:**  
```
python backup_integrity.py gerar /caminho/para/o/diretorio
```

**Dica de uso:** Se o script estiver na pasta raiz do seu backup ou se o seu terminal já estiver aberto dentro do diretório que você deseja mapear, basta utilizar um . (ponto) para indicar o diretório atual:  
```
python backup_integrity.py gerar .
```

**Comportamento Padrão:**

* Cria um arquivo chamado `backup-manifest.json` na raiz do diretório especificado.  
* Utiliza o algoritmo **BLAKE2b** com um *digest* de 32 bytes (256 bits). *Nota: O BLAKE2b é frequentemente mais rápido do que MD5, SHA-1 e SHA-256 em arquiteturas de 64 bits, mantendo alta segurança.*

## **2\. Comando `verificar` (Auditoria de Integridade)**

O subcomando `verificar` compara o estado atual de um diretório com um manifesto previamente gerado.  

**Sintaxe Básica:**  
```
python backup_integrity.py verificar /caminho/para/o/diretorio
```

**Dica de uso:** Assim como no comando de geração, se você já estiver dentro do diretório do backup no terminal, utilize o . (ponto):  
```
python backup_integrity.py verificar .
```

**Comportamento Padrão:**

* Procura automaticamente por um `backup-manifest.json` na raiz do diretório.  
* Gera dois relatórios na raiz do diretório: `backup-verify.log` (formato texto, leitura humana) e `backup-verify.csv` (para ingestão em bancos de dados ou planilhas).

## **Estrutura das Saídas e Relatórios**

### **1\. Arquivo `backup-manifest.json` criado pelo comando `gerar`**

Mantém um registro versionado com *timestamp*, configurações da varredura e um array de files. Cada arquivo armazena path (caminho relativo à raiz, ignorando caminhos absolutos), size, mtime\_ns (timestamp de modificação em nanossegundos) e checksum.

### **2\. Arquivos `backup-verify.log` e `backup-verify.csv` criados pelo comando `verificar`**

São arquivos de relatórios, os quais categorizam as discrepâncias encontradas em 4 tipos cruciais:

1. **Deletados:** Arquivos presentes no manifesto, mas que já não existem no disco. 
2. **Acrescentados:** Arquivos presentes no disco, mas que não existiam quando o manifesto foi gerado.  
3. **Corrompidos/Alterados:** O arquivo existe, mas o *checksum* diverge. Sinal clássico de corrupção de mídia, edição não documentada ou interrupção de cópia.  
4. **Erros de Leitura:** Arquivos bloqueados pelo sistema operacional (ex: permissões restritas, *file locks* ou *bad blocks* no disco).
