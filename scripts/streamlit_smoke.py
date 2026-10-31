"""Exercise the demo UI in Streamlit's actual script runtime without AI calls."""
import argparse
import json
import os
from pathlib import Path

from streamlit.testing.v1 import AppTest

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',default='out/firex-full-demo')
    args=parser.parse_args()
    os.environ['TRACE_DEMO_OUT']=str(Path(args.out).resolve())
    app=AppTest.from_file(str(Path(__file__).resolve().parents[1]/'streamlit_app.py'),default_timeout=60).run()
    assert not app.exception, [e.message for e in app.exception]
    assert len(app.selectbox)>5, 'Incident views did not render'
    next(button for button in app.button if button.label=='Find path').click().run()
    assert not app.exception, [e.message for e in app.exception]
    checkbox=next(widget for widget in app.checkbox if widget.label.startswith('Only incidents'))
    checkbox.check().run()
    assert not app.exception, [e.message for e in app.exception]
    result={'app_render':'passed','path_button':'passed','forecast_incident_filter':'passed',
            'live_ai':'not called','results_directory':str(Path(args.out).resolve())}
    (Path(args.out)/'streamlit-smoke.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps(result,indent=2))
