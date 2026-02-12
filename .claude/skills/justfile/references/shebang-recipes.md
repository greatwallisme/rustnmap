# Shebang Recipes

Shebang recipes (starting with `#!`) allow writing recipes in any language without shell escaping.

## Usage Patterns

```just
# Python recipe - no shell escaping needed
process-data:
  #!/usr/bin/env python3
  import pandas as pd
  df = pd.read_csv('data.csv')
  print(df.describe())

# Node.js recipe
bundle:
  #!/usr/bin/env node
  const esbuild = require('esbuild');
  esbuild.buildSync({ bundle: true });

# Multi-language dependency chain
polyglot: python js perl sh
  echo 'All done'

python:
  #!/usr/bin/env python3
  print('Hello from python!')

js:
  #!/usr/bin/env node
  console.log('Greetings from JavaScript!')

sh:
  #!/usr/bin/env sh
  echo 'Hello from shell!'

# Simple commands still use shell
simple:
  echo 'shell is fine for simple stuff'
```

## Shebang vs Shell Decision

**Use Shebang**:
- Data processing (Python pandas, data analysis)
- API calls (Node.js, Python requests)
- Complex logic (conditionals, loops, error handling)
- Non-trivial programs

**Use Shell**:
- Simple commands
- File operations
- Calling other tools

## Critical Anti-Pattern

**NEVER mix shebang and non-shebang recipes in same dependency chain**
- Causes unpredictable shell behavior
- Each recipe type has different execution model

Bad example:
```just
# BAD - shebang depends on shell recipe
shebang-recipe: shell-recipe
  #!/usr/bin/env python3
  print('This may fail unexpectedly')

shell-recipe:
  echo 'shell setup'
```

Correct approach:
```just
# GOOD - consistent shebang usage
shebang-recipe: shebang-setup
  #!/usr/bin/env python3
  print('Predictable execution')

shebang-setup:
  #!/usr/bin/env python3
  print('Setup complete')
```
