package com.company.frontend.view.regiondto;

import com.company.frontend.entity.RegionDto;
import com.company.frontend.view.main.MainView;
import com.vaadin.flow.router.Route;
import io.jmix.flowui.view.EditedEntityContainer;
import io.jmix.flowui.view.StandardDetailView;
import io.jmix.flowui.view.ViewController;
import io.jmix.flowui.view.ViewDescriptor;

@Route(value = "regionDtoes/:id", layout = MainView.class)
@ViewController(id = "RegionDto.detail")
@ViewDescriptor(path = "region-dto-detail-view.xml")
@EditedEntityContainer("regionDtoDc")
public class RegionDtoDetailView extends StandardDetailView<RegionDto> {

}
