
function isHidden(el) {
  const style = window.getComputedStyle(el);
  const rect = el.getBoundingClientRect();

  return (
    style.display === 'none' ||
    style.visibility === 'hidden' ||
    style.opacity === '0' ||
    rect.width === 0 ||
    rect.height === 0 ||
    el.hasAttribute('hidden') ||
    el.getAttribute('aria-hidden') === 'true'
  );
}

function hiddendata_check(){
  let hiddendata={
    hiddenPasswordFields:0,
    hiddenInputs:0,
    hiddenForms:[]
  }
  const forms=document.querySelectorAll('form');
  forms.forEach(form=>{
    let hiddenFields=[]
    const inputs=form.querySelectorAll('input');
    inputs.forEach(input=>{
      if(isHidden(input)){
        hiddendata.hiddenInputs++;
        hiddenFields.push({
          name: input.name || "unknown",
          type: input.type || "unspecified"
        });
        if(input.type=='password') hiddendata.hiddenPasswordFields++;
      }
    })

    let isformhidden=isHidden(form);
    if(hiddenFields.length || isformhidden){
      hiddendata.hiddenForms.push({
        formElement:form,
        hiddenFields,
        hiddenReasons: isformhidden?["Entire form is hidden"]:["Hidden input files"]
      })
    }
  })
  return hiddendata;
}

