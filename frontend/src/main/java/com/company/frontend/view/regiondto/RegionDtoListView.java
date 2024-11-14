package com.company.frontend.view.regiondto;

import com.company.frontend.entity.RegionDto;
import com.company.frontend.view.main.MainView;
import com.vaadin.flow.router.Route;
import io.jmix.flowui.view.*;

@Route(value = "regionDtoes", layout = MainView.class)
@ViewController(id = "RegionDto.list")
@ViewDescriptor(path = "region-dto-list-view.xml")
@LookupComponent("regionDtoesDataGrid")
@DialogMode(width = "50em")
public class RegionDtoListView extends StandardListView<RegionDto> {

}
