import os
import re

for root, _, files in os.walk('app/routes'):
    for file in files:
        if file.endswith('.py'):
            path = os.path.join(root, file)
            with open(path, 'r') as f:
                content = f.read()
            
            new_content = re.sub(
                r'templates\.TemplateResponse\(([\"\'\w\.]+),\s*(\{.*?\}|context)\)',
                r'templates.TemplateResponse(request=request, name=\1, context=\2)',
                content,
                flags=re.DOTALL
            )
            if new_content != content:
                with open(path, 'w') as f:
                    f.write(new_content)
                print(f'Fixed {path}')
