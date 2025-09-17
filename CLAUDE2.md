## 📋 Visão Geral do Projeto

Este é um sistema distribuído de monitoramento de check-ins em tempo real construído em Go, projetado para garantir a segurança e bem-estar de pessoas através do acompanhamento contínuo de suas atividades. O sistema processa eventos em larga escala com alta disponibilidade, resiliência e escalabilidade horizontal.

### 🎯 Objetivo do Sistema
Monitorar pessoas (assistidos) através de eventos como sinais vitais, localização, rotina ou ausência de atividade esperada, garantindo resposta rápida em situações de emergência ou quando check-ins regulares não são realizados.

## 🏗️ Arquitetura Clean Code com Ports & Adapters

O projeto segue rigorosamente os princípios da **Clean Architecture** com padrão **Hexagonal (Ports & Adapters)**:

### 📐 Estrutura de Camadas

```
🏢 Domain Layer (Centro)
├── 📋 Entities (domain/types.go)
│   ├── Event, User, Contact, Attendant
│   ├── CheckinStatus, NotificationStatus
│   └── Config, TimeWindow
├── 🔌 Ports (Interfaces)
│   ├── CheckinRepository
│   ├── CheckinStreamConsumer/Publisher
│   ├── CheckinNotifier, CheckinUserClient
│   └── CheckinIdempotenceController
└── 📏 Business Rules
    ├── Validation Logic
    ├── Time Window Rules
    └── Escalation Policies

🔧 Application Layer (Use Cases)
├── 🎯 Services (service/)
│   ├── CheckinService (Orchestrator)
│   ├── NotificationManager
│   ├── EscalationManager
│   └── AuditService
└── 📝 DTOs & Converters
    ├── Event Enrichment
    ├── Message Formatting
    └── State Transformation

🔌 Infrastructure Layer (Adapters)
├── 🗄️ Redis Adapters
│   ├── Repository Implementation
│   ├── Stream Consumer/Publisher
│   ├── Notification Scheduler
│   └── Rate Limiter
├── 🌐 HTTP Adapters
│   ├── REST API Receivers
│   ├── User Service Client
│   └── Webhook Notifications
├── 📨 Messaging Adapters
│   ├── WhatsApp Integration
│   ├── SMS Gateway
│   └── Email Service
└── 🔒 Security Adapters
    ├── JWT Authentication
    ├── Token Management
    └── Rate Limiting

🚀 Presentation Layer (Entry Points)
├── 📥 HTTP Receivers (cmd/receiver/)
├── ⚙️ Stream Workers (cmd/checkinMonitor/)
├── 📡 Event Dispatcher (cmd/dispatcher/)
└── 🔧 Management APIs
```

## 🎯 Princípios SOLID Aplicados

### 🔹 **S** - Single Responsibility Principle
- **CheckinService**: Orquestra apenas lógica de check-ins
- **NotificationManager**: Responsável apenas por notificações
- **EscalationManager**: Gerencia apenas escalações
- **AuditService**: Manipula apenas auditoria e métricas

### 🔹 **O** - Open/Closed Principle
- **Notifiers**: Extensível para novos canais (WhatsApp, SMS, Email) sem modificar código existente
- **EventEnrichers**: Novos enriquecedores podem ser adicionados via composição
- **StreamConsumers**: Diferentes tipos de consumidores implementam a mesma interface

### 🔹 **L** - Liskov Substitution Principle
- Todas as implementações de **CheckinRepository** são intercambiáveis
- **MockRepository** pode substituir **RedisRepository** em testes
- **MockUserClient** substitui **HTTPUserClient** sem afetar o comportamento

### 🔹 **I** - Interface Segregation Principle
- **CheckinStreamConsumer** vs **CheckinStreamPublisher** (separadas)
- **CheckinNotifier** específica por canal
- **RedisCommander** contém apenas métodos necessários para cada contexto

### 🔹 **D** - Dependency Inversion Principle
- **CheckinService** depende de abstrações, não implementações concretas
- Todas as dependências são injetadas via construtor
- Infrastructure adapters implementam domain interfaces

## 🧪 Estratégia de Testes de Classe Mundial

### 📊 Cobertura e Qualidade
- **Meta de cobertura**: 95%+ em componentes críticos
- **Testes isolados**: Cada componente testado independentemente
- **Mocks manuais**: Sem dependências de frameworks externos

### 🏗️ Padrões de Teste Implementados

#### 1. **Table-Driven Tests** (Padrão obrigatório)
```go
func TestProcessCheckin(t *testing.T) {
    tests := []struct {
        name           string
        input          *domain.Event
        setupMocks     func(*mocks.MockRepository)
        expectedResult *domain.CheckinStatus
        expectedError  string
    }{
        // Casos de teste...
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Implementação isolada
        })
    }
}
```

#### 2. **Dependency Injection para Testabilidade**
```go
// ✅ Correto: Dependências injetadas
func NewCheckinService(
    repo domain.CheckinRepository,
    notifier domain.CheckinNotifier,
    userClient domain.CheckinUserClient,
) domain.CheckinService {
    return &CheckinService{
        repo:       repo,
        notifier:   notifier,
        userClient: userClient,
    }
}
```

#### 3. **Mocks Manuais Configuráveis**
```go
// MockCheckinRepository implementa domain.CheckinRepository
type MockCheckinRepository struct {
    StoreLastCheckinFunc func(context.Context, *domain.Event) error
    GetLastCheckinFunc   func(context.Context, string) (*domain.Event, error)
}

func (m *MockCheckinRepository) StoreLastCheckin(ctx context.Context, event *domain.Event) error {
    if m.StoreLastCheckinFunc != nil {
        return m.StoreLastCheckinFunc(ctx, event)
    }
    return nil
}
```

#### 4. **Helper Functions com t.Helper()**
```go
func createServiceForTest(t *testing.T, repo *mocks.MockCheckinRepository) *CheckinService {
    t.Helper() // Crucial para stack traces corretos
    
    return NewCheckinService(
        repo,
        mocks.NewMockCheckinNotifier(),
        mocks.NewMockCheckinUserClient(),
    ).(*CheckinService)
}
```

### 🔧 Organização de Mocks

#### Estrutura Padronizada
```
internal/checkinMonitor/mocks/
├── mock_checkin_repository.go      # Persistência
├── mock_checkin_notifier.go        # Notificações
├── mock_checkin_user_client.go     # Cliente HTTP
├── mock_stream_consumer.go         # Consumo de streams
├── mock_stream_publisher.go        # Publicação de streams
├── mock_idempotence_controller.go  # Controle de idempotência
├── mock_escalation_manager.go      # Gerenciamento de escalação
├── mock_notification_manager.go    # Gerenciamento de notificações
├── mock_audit_service.go           # Serviços de auditoria
├── mock_time_provider.go           # Provedor de tempo (testabilidade)
└── mock_logger.go                  # Sistema de logs
```

#### Convenções de Naming
- **Tipo**: `MockNomeInterface`
- **Arquivo**: `mock_nome_interface.go`
- **Constructor**: `NewMockNomeInterface()`
- **Funções configuráveis**: `NomeFuncaoFunc func(...) (...)`

## 🚀 Componentes Principais

### 1. **Event Processing Pipeline**
```
HTTP Request → Event Dispatcher → Redis Streams → Stream Consumer → Business Logic → Notifications
```

### 2. **Checkin Monitoring Flow**
```
Checkin Event → Validation → Enrichment → State Update → Window Check → Escalation (if needed)
```

### 3. **Notification System**
```
Trigger → Rate Limiting → Channel Selection → Message Formatting → Delivery → Confirmation
```

## 🔧 Tecnologias e Padrões

### 🛠️ Stack Tecnológico
- **Go 1.21+**: Linguagem principal
- **Redis**: Streams, cache e armazenamento de estado
- **Redis Gears**: Processamento de eventos (quando necessário)
- **Gin**: Framework web para APIs REST
- **JWT**: Autenticação entre serviços

### 📐 Padrões de Design Aplicados
- **Repository Pattern**: Abstração de persistência
- **Factory Pattern**: Criação de dependências
- **Strategy Pattern**: Diferentes canais de notificação
- **Observer Pattern**: Sistema de eventos
- **Command Pattern**: Processamento de comandos
- **Chain of Responsibility**: Pipeline de processamento

### 📐 Exemplo de Worker 

-- internal/checkinMonitor/service/workers/stream_consumer/worker.go


## 🎯 Guidelines para Desenvolvimento com Claude

### 📝 Ao Solicitar Código
Sempre forneça contexto completo:
```markdown
"Preciso implementar [funcionalidade] no CheckinService seguindo Clean Architecture.
A função deve [requisitos específicos].
Use os mocks existentes em /mocks/ e siga o padrão table-driven test."
```

### 🧪 Ao Solicitar Testes
Use o template padrão:
```markdown
"Considere que sou um desenvolvedor profissional de Go.

Preciso gerar:
1. Testes unitários para a função [nome], seguindo as boas práticas.
2. Um mock separado se necessário (verificar pasta /mocks/).

Regras para o TESTE:
- Table-driven test obrigatório
- Cobertura 100% do código
- t.Helper() para funções auxiliares
- Naming: TestNomeDaFuncao
- t.Run para isolamento
- Apenas testing puro (sem bibliotecas externas)

Regras para o MOCK:
- Mock manual (sem geradores)
- Interface implementation
- Funções configuráveis (campos Func)
- Naming: MockNomeInterface
- Arquivo separado: mock_nome_interface.go
- Constructor: NewMockNomeInterface()
```

### 🔍 Ao Analisar Arquitetura
Sempre mencione:
- Camada atual (Domain/Application/Infrastructure)
- Princípios SOLID sendo aplicados
- Padrões de design utilizados
- Impacto em testabilidade

## 📊 Métricas de Qualidade

### ✅ Indicadores de Sucesso
- **Cobertura de testes**: >95% em componentes críticos
- **Cyclomatic complexity**: <10 por função
- **Dependency injection**: 100% das dependências
- **Interface compliance**: Todas as implementações seguem contratos
- **Test isolation**: Zero dependências entre testes

### 🎯 Objetivos de Performance
- **Latência de processamento**: <100ms para eventos simples
- **Throughput**: >1000 eventos/segundo
- **Disponibilidade**: 99.9% uptime
- **Recovery time**: <5 minutos para falhas

## 🤝 Workflow de Desenvolvimento

### 1. **TDD Approach**
```
Red → Green → Refactor → Document
```

### 2. **Code Review Checklist**
- [ ] Clean Architecture respeitada
- [ ] Princípios SOLID aplicados
- [ ] Testes com cobertura adequada
- [ ] Mocks seguem padrões estabelecidos
- [ ] Dependency injection implementada
- [ ] Error handling robusto

### 3. **Quality Gates**
- [ ] Todos os testes passando
- [ ] Linting sem warnings
- [ ] Cobertura >95% em componentes críticos
- [ ] Documentação atualizada
- [ ] Interfaces bem definidas

## 📚 Recursos e Referências

### 🔗 Documentação Técnica
- [Clean Architecture (Uncle Bob)](https://blog.cleancoder.com/uncle-bob/2012/08/13/the-clean-architecture.html)
- [Hexagonal Architecture](https://alistair.cockburn.us/hexagonal-architecture/)
- [Go Testing Best Practices](https://golang.org/doc/effective_go.html#testing)
- [SOLID Principles in Go](https://dave.cheney.net/2016/08/20/solid-go-design)

### 🛠️ Ferramentas de Desenvolvimento
```bash
# Testes com cobertura
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Análise estática
golangci-lint run

# Geração de documentação
swag init -g cmd/receiver/http-server/main.go
```

---

**Versão**: 2.1  
**Última atualização**: Janeiro 2025  
**Compatibilidade**: Go 1.21+, Redis 6.0+  
**Arquitetura**: Clean Architecture + Hexagonal Pattern  
**Qualidade**: >95% test coverage, SOLID compliant