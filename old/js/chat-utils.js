function auto_height(elem) {
    elem.style.height = "1px";
    elem.style.height = (elem.scrollHeight) + "px";
}

//yoinked from w3school
function searchChannelList() {
    let input = document.getElementById('channel_searchbar');
    let filter = input.value.toUpperCase();
    let ul = document.getElementById("new_channel_token_div");
    let li = ul.getElementsByTagName('li');

    // Loop through all list items, and hide those who don't match the search query
    for (let i = 0; i < li.length; i++) {
        const element = li[i].getElementsByTagName("span")[1];
        const txtValue = element.textContent || element.innerText;
        if (txtValue.toUpperCase().indexOf(filter) > -1) {
            li[i].style.display = "";
        } else {
            li[i].style.display = "none";
        }
    }
}

//yoinked from w3school
function openTab(evt, tabid) {
    let tabcontent = document.getElementsByClassName("tab_section");
    for (let i = 0; i < tabcontent.length; i++) {
        tabcontent[i].style.display = "none";
    }
    let tablinks = document.getElementsByClassName("tabs-btn");
    for (let i = 0; i < tablinks.length; i++) {
        tablinks[i].className = tablinks[i].className.replace(" active", "");
    }
    document.getElementById(tabid).style.display = "flex";
    evt.currentTarget.className += " active";
}

function ToggleSettings() {
    if (document.getElementById("action_menu_class").style.display === "none") document.getElementById("action_menu_class").style.display = "block"; else document.getElementById("action_menu_class").style.display = "none";
}

function DoneLoading() {
    if (document.getElementById("defaultOpen") /*&& chatEngine !== undefined*/) {
        document.getElementById("defaultOpen").click();
    } else {
        setTimeout(() => {
            DoneLoading();      //MUAHAHAHAHAH
        }, 2500);
    }
}

